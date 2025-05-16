package mssql

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/microsoft/go-mssqldb/msdsn"
	"go.uber.org/zap"
)

const (
	defaultServerProgName = "GO MSSQL Server"
	defaultServerVerion   = "v15.0.0"
)

type Client struct {
	logger *zap.Logger
	conn   *Conn
	debug  bool
}

type Server struct {
	logger      *zap.Logger
	connTimeout time.Duration
	packetSize  uint16
	version     uint32
	progName    string
	encryption  byte
	debug       bool
}

type ServerSession struct {
	logger     *zap.Logger
	tdsSession *tdsSession
	debug      bool
}

type ProxyServerOption func(*Server) error

func ProxyServerWithLogger(logger *zap.Logger) ProxyServerOption {
	return func(s *Server) error { s.logger = logger; return nil }
}

func ProxyServerWithConnTimeout(connTimeout time.Duration) ProxyServerOption {
	return func(s *Server) error { s.connTimeout = connTimeout; return nil }
}

func ProxyServerWithPacketSize(packetSize uint16) ProxyServerOption {
	return func(s *Server) error { s.packetSize = packetSize; return nil }
}

func ProxyServerWithVersion(version string) ProxyServerOption {
	return func(s *Server) error { s.version = getDriverVersion(version); return nil }
}

func ProxyServerWithProgramName(progName string) ProxyServerOption {
	return func(s *Server) error { s.progName = progName; return nil }
}

func ProxyServerWithEncryption(encryptionType string) ProxyServerOption {
	return func(s *Server) (err error) {
		switch encryptionType {
		case "strict":
			s.encryption = encryptStrict
			return nil
		case "required":
			s.encryption = encryptReq
			return nil
		case "on":
			s.encryption = encryptOn
			return nil
		case "off":
			s.encryption = encryptOff
			return nil
		default:
			return fmt.Errorf("invalid encryption type option %s, valid values are [ strict, required, on, off ]", encryptionType)
		}
	}
}

func ProxyServerWithDebug(debug bool) ProxyServerOption {
	return func(s *Server) (err error) { s.debug = debug; return nil }
}

func NewProxyServer(opts ...ProxyServerOption) (*Server, error) {
	server := &Server{
		logger:      zap.NewNop(),
		connTimeout: time.Duration(0),
		packetSize:  defaultPacketSize,
		version:     getDriverVersion(defaultServerVerion),
		progName:    defaultServerProgName,
		encryption:  encryptNotSup,
		debug:       false,
	}
	for _, opt := range opts {
		if err := opt(server); err != nil {
			return nil, fmt.Errorf("failed to apply proxy server configuration option: %v", err)
		}
	}

	// Ensure packet size falls within the TDS protocol range of 512 to 32767 bytes
	// NOTE: Encrypted connections have a maximum size of 16383 bytes.  If you request
	// a higher packet size, the server will respond with an ENVCHANGE request to
	// alter the packet size to 16383 bytes.
	if server.packetSize < 512 {
		server.logger.Warn("packet size was set to less than the minimum (512), fixing to 512", zap.Uint16("value_before", server.packetSize))
		server.packetSize = 512
	}
	if server.packetSize > 32767 {
		if server.encryption == encryptStrict || server.encryption == encryptReq || server.encryption == encryptOn {
			server.logger.Warn("packet size was set to more than the maximum for encrypted connections (16383), fixing to 16383", zap.Uint16("value_before", server.packetSize))
			server.packetSize = 16383
		} else {
			server.logger.Warn("packet size was set to more than the maximum (32767), fixing to 32767", zap.Uint16("value_before", server.packetSize))
			server.packetSize = 32767
		}
	}

	return server, nil
}

func (s *Server) ReadLogin(conn net.Conn) (*ServerSession, *login, map[uint8][]byte, error) {
	toconn := newTimeoutConn(conn, s.connTimeout)
	inbuf := newTdsBuffer(s.packetSize, toconn)

	loginOptions, login, err := s.handshake(inbuf)
	if err != nil {
		return nil, nil, loginOptions, err
	}

	sess := ServerSession{
		logger: s.logger,
		tdsSession: &tdsSession{
			buf:    inbuf,
			logger: zapLoggerToContextLogger(s.logger),
			id:     conn.RemoteAddr().String(),
		},
	}

	return &sess, &login, loginOptions, nil
}

func (s *ServerSession) ReadCommand() (packetType, error) {
	var buf []byte

	// FIXME: remove
	if s.debug {
		s.logger.Debug(
			"Start ReadCommand",
			zap.String("tdsSession.id", s.tdsSession.id),
			zap.Int("tdsSession.buf.rpos", s.tdsSession.buf.rpos),
			zap.Int("tdsSession.buf.rsize", s.tdsSession.buf.rsize),
		)
	}

	for {
		// FIXME: REMOVE
		if s.debug {
			s.logger.Debug(
				"ReadCommand",
				zap.String("tdsSession.id", s.tdsSession.id),
				zap.Int("tdsSession.buf.rpos", s.tdsSession.buf.rpos),
				zap.Int("tdsSession.buf.rsize", s.tdsSession.buf.rsize),
			)
		}

		rPacketType, err := s.tdsSession.buf.BeginRead()
		if err != nil {
			// FIXME: REMOVE
			if s.debug {
				s.logger.Debug(
					"ReadCommand error",
					zap.String("tdsSession.id", s.tdsSession.id),
					zap.Error(err),
				)
			}
			return 0, err
		}

		// FIXME: REMOVE
		if s.debug {
			s.logger.Debug(
				"ReadCommand got data",
				zap.Uint8("rPacketType", uint8(rPacketType)),
				zap.String("tdsSession.id", s.tdsSession.id),
				zap.Int("tdsSession.buf.rpos", s.tdsSession.buf.rpos),
				zap.Int("tdsSession.buf.rsize", s.tdsSession.buf.rsize),
			)
		}

		bytes := make([]byte, s.tdsSession.buf.rsize-s.tdsSession.buf.rpos)
		s.tdsSession.buf.ReadFull(bytes)
		s.tdsSession.buf.rPacketType = rPacketType
		buf = append(buf, bytes...)

		if s.tdsSession.buf.final {
			copy(s.tdsSession.buf.rbuf, buf)
			s.tdsSession.buf.rsize = len(buf)
			s.tdsSession.buf.rpos = 0
			return s.tdsSession.buf.rPacketType, nil
		}
	}
}

type doneConfig struct {
	status uint16
	errors []Error
}

type DoneOption func(*doneConfig)

func WithFinal() DoneOption {
	return func(dc *doneConfig) {
		dc.status = dc.status | doneFinal
	}
}

func WithErrors(errs ...Error) DoneOption {
	return func(dc *doneConfig) {
		if len(errs) > 0 {
			dc.status = dc.status | doneSrvError
			dc.errors = errs
		}
	}
}

// SendDone sends the response for a query and optionally marks
// it as final, prompting the client to close the connection.
func (ss *ServerSession) SendDone(opts ...DoneOption) {
	dc := &doneConfig{
		status: uint16(0),
		errors: []Error{},
	}
	for _, opt := range opts {
		opt(dc)
	}
	if _, err := ss.tdsSession.buf.Write(writeDone(doneStruct{Status: dc.status, errors: dc.errors})); err != nil {
		ss.logger.Error("failed to write doneStruct with error to mssql client", zap.Error(err))
	}
}

func (s *Server) handshake(r *tdsBuffer) (map[uint8][]byte, login, error) {
	var login login

	loginOptions, err := s.readPrelogin(r)
	if err != nil {
		return loginOptions, login, err
	}

	// FIXME: REMOVE
	if s.debug {
		s.logger.Info("Client -> Proxy: revieved prelogin options", zap.Any("login_opts", loginOptions))
	}

	err = s.writePrelogin(r)
	if err != nil {
		return loginOptions, login, err
	}

	login, err = s.readLogin(r)
	if err != nil {
		return loginOptions, login, err
	}

	// FIXME: REMOVE
	if s.debug {
		s.logger.Info("Client -> Proxy: revieved login packet ", zap.Any("login_opts", loginOptions))
	}

	return loginOptions, login, nil
}

func (s *Server) readPrelogin(r *tdsBuffer) (map[uint8][]byte, error) {
	packet_type, err := r.BeginRead()
	if err != nil {
		return nil, err
	}
	struct_buf, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	if packet_type != packPrelogin {
		return nil, errors.New("invalid request, expected pre-login packet")
	}
	if len(struct_buf) == 0 {
		return nil, errors.New("invalid empty PRELOGIN request, it must contain at least one byte")
	}

	offset := 0
	results := map[uint8][]byte{}
	for {
		// read prelogin option
		plOption, err := readPreloginOption(struct_buf, offset)
		if err != nil {
			return results, err
		}

		if plOption.token == preloginTERMINATOR {
			break
		}

		// read prelogin option data
		value, err := readPreloginOptionData(plOption, struct_buf)
		if err != nil {
			return results, err
		}
		results[plOption.token] = value

		offset += preloginOptionSize
	}

	return results, nil
}

func (s *Server) writePrelogin(r *tdsBuffer) error {
	fields := s.preparePreloginResponseFields()

	// FIXME: REMOVE
	if s.debug {
		s.logger.Info("Proxy -> Client: returned prelogin response", zap.Any("fields", fields))
	}

	if err := writePrelogin(packReply, r, fields); err != nil {
		return err
	}

	return nil
}

func (s *Server) preparePreloginResponseFields() map[uint8][]byte {
	s.version = getDriverVersion("v15.0.4430.0")
	fields := map[uint8][]byte{
		// 4 bytes for version and 2 bytes for minor version
		preloginVERSION:    {byte(s.version >> 24), byte(s.version >> 16), byte(s.version >> 8), byte(s.version), 0, 0},
		preloginENCRYPTION: {s.encryption},
		preloginINSTOPT:    {0},
		// preloginTHREADID:   {0, 0, 0, 0},
		preloginTHREADID: {},
		preloginMARS:     {0}, // MARS disabled
	}

	return fields
}

func (s *Server) readLogin(r *tdsBuffer) (login, error) {
	var login login
	packet_type, err := r.BeginRead()
	if err != nil {
		return login, err
	}

	if packet_type != packLogin7 {
		return login, errors.New("invalid request, expected login packet")
	}

	struct_buf, err := io.ReadAll(r)
	if err != nil {
		return login, err
	}

	if len(struct_buf) == 0 {
		return login, errors.New("invalid empty login request, it must contain at least one byte")
	}

	var loginHeader loginHeader
	if err := binary.Read(bytes.NewReader(struct_buf), binary.LittleEndian, &loginHeader); err != nil {
		return login, fmt.Errorf("failed to read login packet: %w", err)
	}

	login.TDSVersion = loginHeader.TDSVersion
	login.ClientProgVer = loginHeader.ClientProgVer
	login.ClientPID = loginHeader.ClientPID
	login.ConnectionID = loginHeader.ConnectionID
	login.OptionFlags1 = loginHeader.OptionFlags1
	login.OptionFlags2 = loginHeader.OptionFlags2
	login.TypeFlags = loginHeader.TypeFlags
	login.OptionFlags3 = loginHeader.OptionFlags3
	login.ClientTimeZone = loginHeader.ClientTimeZone
	login.ClientLCID = loginHeader.ClientLCID
	login.ClientID = loginHeader.ClientID

	login.HostName, err = readLoginFieldString(struct_buf, loginHeader.HostNameOffset, loginHeader.HostNameLength)
	if err != nil {
		return login, fmt.Errorf("failed to read hostname: %w", err)
	}
	login.UserName, err = readLoginFieldString(struct_buf, loginHeader.UserNameOffset, loginHeader.UserNameLength)
	if err != nil {
		return login, fmt.Errorf("failed to read username: %w", err)
	}
	login.AppName, err = readLoginFieldString(struct_buf, loginHeader.AppNameOffset, loginHeader.AppNameLength)
	if err != nil {
		return login, fmt.Errorf("failed to read username: %w", err)
	}
	login.ServerName, err = readLoginFieldString(struct_buf, loginHeader.ServerNameOffset, loginHeader.ServerNameLength)
	if err != nil {
		return login, fmt.Errorf("failed to read servername: %w", err)
	}
	login.CtlIntName, err = readLoginFieldString(struct_buf, loginHeader.CtlIntNameOffset, loginHeader.CtlIntNameLength)
	if err != nil {
		return login, fmt.Errorf("failed to read servername: %w", err)
	}
	login.Language, err = readLoginFieldString(struct_buf, loginHeader.LanguageOffset, loginHeader.LanguageLength)
	if err != nil {
		return login, fmt.Errorf("failed to read servername: %w", err)
	}
	login.Database, err = readLoginFieldString(struct_buf, loginHeader.DatabaseOffset, loginHeader.DatabaseLength)
	if err != nil {
		return login, fmt.Errorf("failed to read servername: %w", err)
	}
	// FIXME: REMOVE
	if s.debug {
		s.logger.Info("Database name in login request", zap.String("dbname", login.Database))
	}
	login.SSPI, err = readLoginFieldBytes(struct_buf, loginHeader.SSPIOffset, loginHeader.SSPILength)
	if err != nil {
		return login, fmt.Errorf("failed to read sspi: %w", err)
	}
	login.AtchDBFile, err = readLoginFieldString(struct_buf, loginHeader.AtchDBFileOffset, loginHeader.AtchDBFileLength)
	if err != nil {
		return login, fmt.Errorf("failed to read sspi: %w", err)
	}
	login.ChangePassword, err = readLoginFieldString(struct_buf, loginHeader.ChangePasswordOffset, loginHeader.ChangePasswordLength)
	if err != nil {
		return login, fmt.Errorf("failed to read sspi: %w", err)
	}

	// Read FeatureExt if present
	if loginHeader.OptionFlags3&0x10 != 0 && loginHeader.ExtensionOffset != 0 {
		if int(loginHeader.ExtensionOffset)+4 > len(struct_buf) {
			return login, fmt.Errorf("cannot read ibFeatureExtLong at offset %d", loginHeader.ExtensionOffset)
		}
		extPtr := binary.LittleEndian.Uint32(struct_buf[loginHeader.ExtensionOffset : loginHeader.ExtensionOffset+4])
		extStart := int(extPtr)
		if extStart+1 > len(struct_buf) {
			return login, fmt.Errorf("invalid FeatureExt pointer: not enough bytes at offset %d", extStart)
		}

		// FIXME: REMOVE
		if s.debug {
			s.logger.Info("Proxy-Client: starting FeatureExt parse from offset", zap.Int("extStart", extStart))
		}

		reader := bytes.NewReader(struct_buf[extStart:])
		for {
			featureID, err := reader.ReadByte()
			if err != nil {
				return login, fmt.Errorf("failed to read FeatureID: %w", err)
			}
			if featureID == 0xFF {
				break
			}

			var featureDataLen uint32
			if err := binary.Read(reader, binary.LittleEndian, &featureDataLen); err != nil {
				return login, fmt.Errorf("failed to read FeatureDataLength for FeatureID 0x%X: %w", featureID, err)
			}

			if int(featureDataLen) > reader.Len() {
				return login, fmt.Errorf("declared FeatureDataLength (%d) exceeds remaining buffer (%d) for FeatureID 0x%X", featureDataLen, reader.Len(), featureID)
			}

			data := make([]byte, featureDataLen)
			if _, err := io.ReadFull(reader, data); err != nil {
				return login, fmt.Errorf("failed to read FeatureData for FeatureID 0x%X: %w", featureID, err)
			}

			switch featureID {
			case 0x01:
				login.FeatureExt.Add(&featureExtSessionRecovery{})
			case 0x04:
				login.FeatureExt.Add(&featureExtColumnEncryption{
					version: data[0],
				})
			case 0x5:
				login.FeatureExt.Add(&featureExtGlobalTransactions{})
			case 0x09:
				login.FeatureExt.Add(&featureExtDataClassification{
					version: data[0],
				})
			case 0x0A:
				login.FeatureExt.Add(&featureExtUTF8Support{})
			case 0x0B:
				login.FeatureExt.Add(&featureExtAzureSQLDNSCaching{})
			default:
				// FIXME: REMOVE
				if s.debug {
					s.logger.Error("Proxy-Client: unknown FeatureExt ID", zap.Uint8("featureID", featureID), zap.Uint32("featureDataLen", featureDataLen))
				}
				return login, fmt.Errorf("unknown FeatureExt ID 0x%02X", featureID)
			}
			// FIXME: REMOVE
			if s.debug {
				s.logger.Info("FeatureExt", zap.Uint8("featureID", featureID), zap.Uint32("featureDataLen", featureDataLen), zap.Binary("data", data))
			}
		}
	}

	if s.debug {
		fmt.Printf("\n--- TDS LOGIN PACKET SUMMARY ---\n")
		fmt.Printf("TDS Version: 0x%08X\n", login.TDSVersion)
		fmt.Printf("Client PID: %d\n", login.ClientPID)
		fmt.Printf("OptionFlags1: 0x%02X\n", login.OptionFlags1)
		fmt.Printf("OptionFlags2: 0x%02X\n", login.OptionFlags2)
		fmt.Printf("OptionFlags3: 0x%02X\n", login.OptionFlags3)
		fmt.Printf("Client Time Zone: %d\n", login.ClientTimeZone)
		fmt.Printf("Client LCID: 0x%08X\n", login.ClientLCID)
		fmt.Printf("Client ID: % X\n", login.ClientID[:])
		fmt.Printf("HostName: %s\n", login.HostName)
		fmt.Printf("UserName: %s\n", login.UserName)
		fmt.Printf("AppName: %s\n", login.AppName)
		fmt.Printf("ServerName: %s\n", login.ServerName)
		fmt.Printf("CtlIntName: %s\n", login.CtlIntName)
		fmt.Printf("Language: %s\n", login.Language)
		fmt.Printf("Database: %s\n", login.Database)
		fmt.Printf("AttachDBFile: %s\n", login.AtchDBFile)
		fmt.Printf("ChangePassword: %s\n", login.ChangePassword)
		fmt.Printf("SSPI: % X\n", login.SSPI)
		fmt.Printf("FeatureExt: % X\n", login.FeatureExt)
		fmt.Printf("--- END LOGIN PACKET SUMMARY ---\n\n")
	}
	return login, nil
}

func readLoginFieldString(b []byte, offset uint16, length uint16) (string, error) {
	if len(b) < int(offset)+int(length)*2 {
		return "", fmt.Errorf("invalid login packet, expected %d bytes, got %d", offset+length*2, len(b))
	}

	return ucs22str(b[offset : offset+length*2])
}

func readLoginFieldBytes(b []byte, offset uint16, length uint16) ([]byte, error) {
	if len(b) < int(offset)+int(length) {
		return nil, fmt.Errorf("invalid login packet, expected %d bytes, got %d", offset+length, len(b))
	}

	return b[offset : offset+length], nil
}

func (s *Server) WriteLogin(session *ServerSession, loginTokens []tokenStruct, spid uint16) error {
	// FIXME: REMOVE
	if s.debug {
		s.logger.Info("Proxy-Client: Writing login tokens", zap.Any("login_tokens", loginTokens))
	}
	loginAck := loginAckStruct{
		Interface:  1,
		TDSVersion: verTDS74,
		ProgName:   s.progName,
		ProgVer:    s.version,
	}

	done := doneStruct{
		Status:   0,
		CurCmd:   0,
		RowCount: 0,
		errors:   []Error{},
	}

	session.tdsSession.buf.wSpid = spid
	session.tdsSession.buf.BeginPacket(packReply, false)
	// session.tdsSession.buf.Write(loginEnvBytes)
	// session.tdsSession.buf.Write(writeLoginAck(loginAckStruct))
	// session.tdsSession.buf.Write(writeDone(doneStruct))
	for _, token := range loginTokens {
		switch t := token.(type) {
		case loginAckStruct:
			if _, err := session.tdsSession.buf.Write(writeLoginAck(t)); err != nil {
				// FIXME: REMOVE
				if s.debug {
					s.logger.Info("Proxy-Client: Error writing loginAck", zap.Error(err))
				}
				return err
			}
			// FIXME: REMOVE
			if s.debug {
				s.logger.Info("Proxy-Client: Error writing loginAck", zap.Any("loginAck", loginAck))
			}
		case doneStruct:
			if _, err := session.tdsSession.buf.Write(writeDone(done)); err != nil {
				// FIXME: REMOVE
				if s.debug {
					s.logger.Error("Proxy-Client: Error writing doneStruct", zap.Error(err))
				}
				return err
			}
			// FIXME: REMOVE
			if s.debug {
				s.logger.Info("Proxy-Client: Writing doneStruct", zap.Any("done", done))
			}
		case envChange:
			data := make([]byte, 0, len(t.data)+3)
			data = append(data, byte(tokenEnvChange))
			// append length of data as uint16 in little-endian order
			lenBytes := make([]byte, 2)
			binary.LittleEndian.PutUint16(lenBytes, uint16(len(t.data)))
			data = append(data, lenBytes...)
			data = append(data, t.data...)

			if _, err := session.tdsSession.buf.Write(data); err != nil {
				// FIXME: REMOVE
				if s.debug {
					s.logger.Info("Proxy-Client: Error writing envChange", zap.Error(err))
				}
				return err
			}
			// FIXME: REMOVE
			if s.debug {
				s.logger.Info("Proxy-Client: Writing envChange", zap.Any("data", data))
			}
		case loginToken:
			data := make([]byte, 0, len(t.data)+3)
			data = append(data, byte(t.token))
			// append length of data as uint16 in little-endian order
			lenBytes := make([]byte, 2)
			binary.LittleEndian.PutUint16(lenBytes, uint16(len(t.data)))
			data = append(data, lenBytes...)

			data = append(data, t.data...)

			if _, err := session.tdsSession.buf.Write(data); err != nil {
				// FIXME: REMOVE
				if s.debug {
					s.logger.Info("Proxy-Client: Error writing loginToken", zap.Error(err))
				}
				return err
			}
			// FIXME: REMOVE
			if s.debug {
				s.logger.Info("Proxy-Client: Writing loginToken", zap.Any("token", t.token))
			}
		case featureExtAck:
			// FIXME: REMOVE
			if s.debug {
				s.logger.Info("Proxy-Client: Writing featureExtAck", zap.Any("token", t))
			}
			// Serialize the raw feature ACK data (feature entries + terminator)
			var rawBuf bytes.Buffer
			if err := writeFeatureExtAck(&rawBuf, t); err != nil {
				// FIXME: REMOVE
				if s.debug {
					s.logger.Error("Proxy-Client: Error building featureExtAck", zap.Error(err))
				}
				return err
			}
			raw := rawBuf.Bytes()
			// Write token type
			if err := session.tdsSession.buf.WriteByte(byte(tokenFeatureExtAck)); err != nil {
				return err
			}
			// Write length of feature data (uint32 little-endian)
			// lenBuf := make([]byte, 4)
			// binary.LittleEndian.PutUint32(lenBuf, uint32(len(raw)))
			// if _, err := session.buf.Write(lenBuf); err != nil {
			// 	return err
			// }
			// Write the feature data itself
			if _, err := session.tdsSession.buf.Write(raw); err != nil {
				return err
			}
			// FIXME: REMOVE
			if s.debug {
				s.logger.Error("Proxy-Client: featureExtAck raw bytes written", zap.Int("len", len(raw)))
			}
		default:
			fmt.Printf("Proxy-Client: Unknown token type: %T\n", t)
		}
	}

	// FIXME: REMOVE
	if s.debug {
		fmt.Printf("Proxy-Client: Writing loginTokens %+v\n", loginTokens)
		fmt.Printf("Proxy-Client: Writing loginAck %+v\n", loginAck)
		fmt.Printf("Proxy-Client: Writing doneStruct %+v\n", done)
	}

	return session.tdsSession.buf.FinishPacket()
}

func (c *Conn) Transport() io.ReadWriteCloser {
	if c.sess == nil || c.sess.buf == nil {
		return nil
	}

	return c.sess.buf.transport
}

func (c *Conn) Buffer() *tdsBuffer {
	if c.sess == nil || c.sess.buf == nil {
		return nil
	}

	return c.sess.buf
}

func (c *Conn) Session() *tdsSession {
	return c.sess
}

func (s *ServerSession) ParseHeader() (header, error) {
	var h header
	err := binary.Read(s.tdsSession.buf, binary.LittleEndian, &h)
	if err != nil {
		return header{}, err
	}
	return h, nil
}

func (s *ServerSession) ParseSQLBatch() ([]headerStruct, string, error) {
	// FIXME: REMOVE
	if s.debug {
		s.logger.Debug("ParseSQLBatch",
			zap.String("tdsSession.id", s.tdsSession.id),
			zap.Int("tdsSession.buf.rsize", s.tdsSession.buf.rsize),
			zap.Int("tdsSession.buf.rpos", s.tdsSession.buf.rpos),
		)
	}

	headers, err := readAllHeaders(s.tdsSession.buf)
	if err != nil {
		return nil, "", err
	}

	// FIXME: REMOVE
	if s.debug {
		s.logger.Debug("ParseSQLBatch headers", zap.Any("headers", headers))
	}

	query, err := readUcs2(s.tdsSession.buf, (s.tdsSession.buf.rsize-s.tdsSession.buf.rpos)/2)
	if err != nil {
		return nil, "", err
	}

	// FIXME: REMOVE
	if s.debug {
		s.logger.Debug("ParseSQLBatch query", zap.String("query", query))
	}

	return headers, query, nil
}

func (s *ServerSession) ParseTransMgrReq() ([]headerStruct, uint16, isoLevel, string, string, uint8, error) {
	headers, err := readAllHeaders(s.tdsSession.buf)
	if err != nil {
		return nil, 0, 0, "", "", 0, err
	}

	var rqtype uint16
	if err := binary.Read(s.tdsSession.buf, binary.LittleEndian, &rqtype); err != nil {
		return nil, 0, 0, "", "", 0, err
	}

	switch rqtype {
	case tmBeginXact:
		var isolationLevel isoLevel
		if err := binary.Read(s.tdsSession.buf, binary.LittleEndian, &isolationLevel); err != nil {
			return nil, 0, 0, "", "", 0, err
		}

		name, err := readBVarChar(s.tdsSession.buf)
		if err != nil {
			return nil, 0, 0, "", "", 0, err
		}

		return headers, rqtype, isolationLevel, name, "", 0, nil
	case tmCommitXact, tmRollbackXact:
		name, err := readBVarChar(s.tdsSession.buf)
		if err != nil {
			return nil, 0, 0, "", "", 0, err
		}

		var flags uint8
		if err := binary.Read(s.tdsSession.buf, binary.LittleEndian, &flags); err != nil {
			return nil, 0, 0, "", "", 0, err
		}

		var newname string
		if flags&fBeginXact != 0 {
			var isolationLevel isoLevel
			if err := binary.Read(s.tdsSession.buf, binary.LittleEndian, &isolationLevel); err != nil {
				return nil, 0, 0, "", "", 0, err
			}

			newname, err = readBVarChar(s.tdsSession.buf)
			if err != nil {
				return nil, 0, 0, "", "", 0, err
			}
		}

		return headers, rqtype, 0, name, newname, flags, nil
	default:
		return nil, 0, 0, "", "", 0, fmt.Errorf("invalid transaction manager request type: %d", rqtype)
	}
}

// // readParamMeta consumes the parameter's type metadata and returns a filled typeInfo.
// // For legacy TEXT and NTEXT, it skips max-length and collation before using the simple reader.
// // For IMAGE, it skips only max-length. All other types use the normal readTypeInfo path.
// func readParamMeta(b *tdsBuffer, enc msdsn.EncodeParameters) typeInfo {
// 	// Read the type token
// 	typeByte := b.byte()
// 	fmt.Printf("readParamMeta: typeByte %d\n", typeByte)

// 	switch typeByte {
// 	case typeText, typeNText:
// 		// Skip max length (2 bytes)
// 		var maxLen uint16
// 		if err := binary.Read(b, binary.LittleEndian, &maxLen); err != nil {
// 			panic(err)
// 		}
// 		// Skip collation (5 bytes)
// 		if _, err := io.ReadFull(b, make([]byte, 5)); err != nil {
// 			panic(err)
// 		}
// 		return typeInfo{TypeId: typeByte, Reader: readSimpleParam}

// 	case typeImage:
// 		// Skip max length (2 bytes)
// 		var maxLen uint16
// 		if err := binary.Read(b, binary.LittleEndian, &maxLen); err != nil {
// 			panic(err)
// 		}
// 		return typeInfo{TypeId: typeByte, Reader: readSimpleParam}

// 	default:
// 		// All other types: consume full metadata and field-specific reader via readTypeInfo
// 		return readTypeInfo(b, typeByte, nil, enc)
// 	}
// }

func (s *ServerSession) ParseRPC(logger *zap.Logger) ([]headerStruct, procId, uint16, []param, []any, error) {
	headers, err := readAllHeaders(s.tdsSession.buf)
	if err != nil {
		return nil, procId{}, 0, nil, nil, err
	}

	if s.debug {
		s.logger.Debug(
			"Start ParseRPC",
			zap.String("tdsSession.id", s.tdsSession.id),
			zap.Int("tdsSession.buf.rpos", s.tdsSession.buf.rpos),
			zap.Int("tdsSession.buf.rsize", s.tdsSession.buf.rsize),
		)
	}

	var nameLength uint16
	if err := binary.Read(s.tdsSession.buf, binary.LittleEndian, &nameLength); err != nil {
		return nil, procId{}, 0, nil, nil, err
	}

	var proc procId
	var idswitch uint16 = 0xffff
	if nameLength == idswitch {
		if err := binary.Read(s.tdsSession.buf, binary.LittleEndian, &proc.id); err != nil {
			return nil, procId{}, 0, nil, nil, err
		}
	} else {
		proc.name, err = readUcs2(s.tdsSession.buf, int(nameLength))
		if err != nil {
			return nil, procId{}, 0, nil, nil, err
		}
	}

	var flags uint16
	if err := binary.Read(s.tdsSession.buf, binary.LittleEndian, &flags); err != nil {
		return nil, procId{}, 0, nil, nil, err
	}

	params, values, err := parseParams(logger, s.tdsSession.buf, s.tdsSession.encoding)
	if err != nil {
		return nil, procId{}, 0, nil, nil, err
	}

	if s.debug {
		s.logger.Debug(
			"ParseRPC params parsed",
			zap.String("tdsSession.id", s.tdsSession.id),
			zap.Int("tdsSession.buf.rpos", s.tdsSession.buf.rpos),
			zap.Int("tdsSession.buf.rsize", s.tdsSession.buf.rsize),
			zap.Bool("tdsSession.buf.final", s.tdsSession.buf.final),
		)
	}

	return headers, proc, flags, params, values, nil
}

func parseParams(logger *zap.Logger, b *tdsBuffer, encoding msdsn.EncodeParameters) ([]param, []any, error) {
	var (
		params []param
		values []any
	)

	const (
		TDS_RPC_OUTPUT = 0x1
		TDS_RPC_NODEF  = 0x2
	)

	for {
		// stop when buffer is exhausted
		if b.rpos >= b.rsize {
			break
		}

		// dump next bytes for context
		nextEnd := b.rpos + 32
		if nextEnd > b.rsize {
			nextEnd = b.rsize
		}

		var p param

		// name
		name, err := readBVarChar(b)
		if err != nil {
			return nil, nil, err
		}
		p.Name = name

		// flags
		if err := binary.Read(b, binary.LittleEndian, &p.Flags); err != nil {
			return nil, nil, err
		}

		// always parse type metadata to keep cursor aligned
		p.ti = readParamTypeInfo(b, b.byte(), nil, encoding)

		// // OUTPUT-only: skip without consuming data
		// if p.Flags&TDS_RPC_OUTPUT != 0 {
		// 	fmt.Printf("parseParams: param %q is OUTPUT-only\n", p.Name)
		// 	params = append(params, p)
		// 	values = append(values, nil)
		// 	continue
		// }
		// // BYREF: consume and drop client-sent value to stay aligned
		// if p.Flags&paramByRef != 0 {
		// 	fmt.Printf("parseParams: about to read value for param %q at pos=%d, rsize=%d\n", p.Name, b.rpos, b.rsize)
		// 	fmt.Printf("parseParams: param %q is BYREF\n", p.Name)
		// 	_ = p.ti.Reader(&p.ti, b, nil)
		// 	params = append(params, p)
		// 	values = append(values, nil)
		// 	continue
		// }

		// normal IN parameter → read value
		val := p.ti.Reader(&p.ti, b, nil)
		p.buffer = p.ti.Buffer
		params = append(params, p)
		values = append(values, val)
	}

	return params, values, nil
}

func readAllHeaders(r io.Reader) ([]headerStruct, error) {
	var totalLength uint32
	err := binary.Read(r, binary.LittleEndian, &totalLength)
	if err != nil {
		return nil, err
	}

	if totalLength < 4 {
		return nil, errors.New("invalid total length")
	}

	var headers []headerStruct
	remainingLength := totalLength - 4 // Subtracting the length of the totalLength field

	for remainingLength > 0 {
		var headerLength uint32
		err = binary.Read(r, binary.LittleEndian, &headerLength)
		if err != nil {
			return nil, err
		}

		if headerLength < 6 || headerLength-6 > remainingLength {
			return nil, errors.New("invalid header length")
		}

		var hdrtype uint16
		err = binary.Read(r, binary.LittleEndian, &hdrtype)
		if err != nil {
			return nil, err
		}

		dataLength := headerLength - 6 // Subtracting the length of the headerLength and hdrtype fields
		data := make([]byte, dataLength)
		_, err = io.ReadFull(r, data)
		if err != nil {
			return nil, err
		}

		headers = append(headers, headerStruct{
			hdrtype: hdrtype,
			data:    data,
		})

		remainingLength -= headerLength
	}

	if remainingLength != 0 {
		return nil, errors.New("inconsistent header length")
	}

	return headers, nil
}

func (p *procId) Id() uint16 {
	return p.id
}

func (p *procId) Name() string {
	return p.name
}

func writeDone(d doneStruct) []byte {
	data := make([]byte, 0, 12)

	// Append tokenDone and the calculated size
	data = append(data, byte(tokenDone))

	// Append Status
	statusBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(statusBytes, d.Status)
	data = append(data, statusBytes...)

	// Append CurCmd
	curCmdBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(curCmdBytes, d.CurCmd)
	data = append(data, curCmdBytes...)

	// Append RowCount
	rowCountBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(rowCountBytes, d.RowCount)
	data = append(data, rowCountBytes...)

	return data
}

func writeLoginAck(l loginAckStruct) []byte {
	progNameUCS2 := str2ucs2(l.ProgName)

	// Prepare the slice with preallocated size for efficiency
	data := make([]byte, 0, 10+len(progNameUCS2))

	// Append tokenLoginAck
	data = append(data, byte(tokenLoginAck))

	// Append calculated size
	size := uint16(10 + len(progNameUCS2))
	sizeBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(sizeBytes, size)
	data = append(data, sizeBytes...)

	// Append Interface
	data = append(data, l.Interface)

	// Append TDSVersion
	tdsVersionBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tdsVersionBytes, l.TDSVersion)
	data = append(data, tdsVersionBytes...)

	// Append ProgName Length and ProgName
	data = append(data, byte(len(progNameUCS2)/2))
	data = append(data, progNameUCS2...)

	// Append ProgVer
	progVerBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(progVerBytes, l.ProgVer)
	data = append(data, progVerBytes...)

	return data
}

func NewConnectorFromConfig(config msdsn.Config) *Connector {
	return newConnector(config, driverInstanceNoProcess)
}

func NewClient(ctx context.Context, logger *zap.Logger, c *Connector, dialer Dialer, database string) (*Client, error) {
	border0DebugLogs := strings.ToLower(os.Getenv("BORDER0_MSSQL_PROXY_DEBUG")) == "true"

	if dialer != nil {
		c.Dialer = dialer
	}

	params := c.params
	params.Database = database
	if border0DebugLogs {
		fmt.Printf("NewClient: %+v\n", params)
	}

	conn, err := c.driver.connect(ctx, c, params)
	if err != nil {
		return nil, err
	}

	if err := conn.ResetSession(ctx); err != nil {
		return nil, err
	}

	return &Client{
		conn:   conn,
		logger: logger,
		debug:  border0DebugLogs,
	}, nil
}

func (c *Client) ConnSpid() uint16 {
	return c.conn.sess.buf.rSpid
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) SendSqlBatch(ctx context.Context, serverConn *ServerSession, query string, headers []headerStruct, resetSession bool) ([]doneStruct, error) {
	if err := sendSqlBatch72(c.conn.sess.buf, query, headers, resetSession); err != nil {
		return nil, err
	}

	return c.processResponse(ctx, serverConn)
}

func (c *Client) SendRpc(ctx context.Context, serverConn *ServerSession, headers []headerStruct, proc procId, flags uint16, params []param, resetSession bool) ([]doneStruct, error) {
	if err := sendRpc(c.conn.sess.buf, headers, proc, flags, params, resetSession, c.conn.sess.encoding); err != nil {
		return nil, err
	}
	return c.processResponse(ctx, serverConn)
}

func (c *Client) TransMgrReq(ctx context.Context, serverConn *ServerSession, headers []headerStruct, rqtype uint16, isolationLevel isoLevel, name, newname string, flags uint8, resetSession bool) ([]doneStruct, error) {
	switch rqtype {
	case tmBeginXact:
		if err := sendBeginXact(c.conn.sess.buf, headers, isolationLevel, name, resetSession); err != nil {
			return nil, err
		}
	case tmCommitXact:
		if err := sendCommitXact(c.conn.sess.buf, headers, name, flags, uint8(isolationLevel), newname, resetSession); err != nil {
			return nil, err
		}
	case tmRollbackXact:
		if err := sendRollbackXact(c.conn.sess.buf, headers, name, flags, uint8(isolationLevel), newname, resetSession); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("invalid transaction manager request type: %d", rqtype)
	}

	return c.processResponse(ctx, serverConn)
}

func (c *Client) processResponse(
	ctx context.Context,
	sess *ServerSession,
) ([]doneStruct, error) {
	c.conn.sess.buf.serverConn = sess.tdsSession

	packet_type, err := c.conn.sess.buf.BeginRead()
	if err != nil {
		switch e := err.(type) {
		case *net.OpError:
			return nil, e
		default:
			return nil, &net.OpError{Op: "Read", Err: err}
		}
	}

	if packet_type != packReply {
		return nil, StreamError{
			InnerError: fmt.Errorf("unexpected packet type in reply: got %v, expected %v", packet_type, packReply),
		}
	}

	var dones []doneStruct
	var columns []columnStruct
	var errs []Error
	for {
		token := token(c.conn.sess.buf.byte())
		if c.debug {
			fmt.Printf("processResponse: %s token %d\n", c.conn.sess.id, token)
		}
		switch token {
		case tokenReturnStatus:
			parseReturnStatus(c.conn.sess.buf)
		case tokenOrder:
			parseOrder(c.conn.sess.buf)
		case tokenDone, tokenDoneProc, tokenDoneInProc:
			res := parseDone(c.conn.sess.buf)
			res.errors = errs
			dones = append(dones, res)
			if res.Status&doneSrvError != 0 {
				return dones, ServerError{res.getError()}
			}

			if res.Status&doneMore == 0 {
				return dones, nil
			}
		case tokenColMetadata:
			columns = parseColMetadata72(c.conn.sess.buf, c.conn.sess)
		case tokenRow:
			row := make([]interface{}, len(columns))
			err = parseRow(ctx, c.conn.sess.buf, c.conn.sess, columns, row)
			if err != nil {
				return nil, StreamError{
					InnerError: fmt.Errorf("failed to parse row: %w", err),
				}
			}
		case tokenNbcRow:
			row := make([]interface{}, len(columns))
			err = parseNbcRow(ctx, c.conn.sess.buf, c.conn.sess, columns, row)
			if err != nil {
				return nil, StreamError{
					InnerError: fmt.Errorf("failed to parse row: %w", err),
				}
			}
		case tokenEnvChange:
			processEnvChg(ctx, c.conn.sess)
		case tokenError:
			err := parseError72(c.conn.sess.buf)
			errs = append(errs, err)
		case tokenInfo:
			parseInfo(c.conn.sess.buf)
		case tokenReturnValue:
			parseReturnValue(c.conn.sess.buf, c.conn.sess)
		case tokenSessionState:
			// Read the total length of the SESSIONSTATE token (excluding TokenType and this Length field itself)
			var totalLen uint32
			if err := binary.Read(c.conn.sess.buf, binary.LittleEndian, &totalLen); err != nil {
				return nil, StreamError{
					InnerError: fmt.Errorf("failed to read SESSIONSTATE length: %w", err),
				}
			}

			// Read SeqNo (4 bytes)
			var seqNo uint32
			if err := binary.Read(c.conn.sess.buf, binary.LittleEndian, &seqNo); err != nil {
				return nil, StreamError{
					InnerError: fmt.Errorf("failed to read SESSIONSTATE SeqNo: %w", err),
				}
			}

			// Read Status (1 byte)
			status, err := c.conn.sess.buf.ReadByte()
			if err != nil {
				return nil, StreamError{
					InnerError: fmt.Errorf("failed to read SESSIONSTATE Status: %w", err),
				}
			}
			fRecoverable := status&0x01 == 0x01

			// FIXME: REMOVE
			if c.debug {
				fmt.Printf("processResponse: SESSIONSTATE received - TotalLen=%d, SeqNo=%d, fRecoverable=%v\n", totalLen, seqNo, fRecoverable)
			}

			bytesLeft := int(totalLen - 5) // minus SeqNo (4) + Status (1)
			for bytesLeft > 0 {
				stateID, err := c.conn.sess.buf.ReadByte()
				if err != nil {
					return nil, StreamError{
						InnerError: fmt.Errorf("failed to read StateId: %w", err),
					}
				}

				lenByte, err := c.conn.sess.buf.ReadByte()
				if err != nil {
					return nil, StreamError{
						InnerError: fmt.Errorf("failed to read StateLen byte: %w", err),
					}
				}
				bytesLeft -= 2 // 1 for stateID, 1 for lenByte

				var stateLen int
				if lenByte == 0xFF {
					var longLen uint32
					if err := binary.Read(c.conn.sess.buf, binary.LittleEndian, &longLen); err != nil {
						return nil, StreamError{
							InnerError: fmt.Errorf("failed to read extended StateLen: %w", err),
						}
					}
					stateLen = int(longLen)
					bytesLeft -= 4
				} else {
					stateLen = int(lenByte)
				}
				bytesLeft -= stateLen

				stateValue := make([]byte, stateLen)
				if _, err := io.ReadFull(c.conn.sess.buf, stateValue); err != nil {
					return nil, StreamError{
						InnerError: fmt.Errorf("failed to read StateValue: %w", err),
					}
				}

				if c.debug {
					fmt.Printf("SESSIONSTATE: StateID=0x%02X, Length=%d, Value=% X\n", stateID, stateLen, stateValue)
				}
			}
		default:
			c.logger.Error("unknown token type", zap.Error(fmt.Errorf("unknown token type returned: %v", token)))
			return nil, StreamError{
				InnerError: fmt.Errorf("unknown token type returned: %v", token),
			}
		}
	}
}

func (d doneStruct) GetError() error {
	n := len(d.errors)
	if n == 0 {
		return nil
	}

	var err error

	for _, e := range d.errors {
		err = errors.Join(err, e)
	}

	return err
}

func (c *Client) LoginTokens() []tokenStruct {
	return c.conn.sess.loginTokens
}

func (c *Client) Database() string {
	return c.conn.sess.database
}

func (c *Client) SendAttention(ctx context.Context, serverConn *ServerSession) ([]doneStruct, error) {
	if err := sendAttention(c.conn.sess.buf); err != nil {
		return nil, err
	}

	return c.processResponse(ctx, serverConn)
}

// func readSimpleParam(ti *typeInfo, r *tdsBuffer, _ *cryptoMetadata) interface{} {
// 	fmt.Printf("[readSimpleParam] rpos before read = %d, rsize = %d\n", r.rpos, r.rsize)

// 	// Length (int32)
// 	if r.rpos+4 > r.rsize {
// 		fmt.Printf("[readSimpleParam] not enough bytes to read length (rpos=%d, rsize=%d)\n", r.rpos, r.rsize)
// 		return nil
// 	}
// 	length := int32(binary.LittleEndian.Uint32(r.rbuf[r.rpos:]))
// 	r.rpos += 4
// 	fmt.Printf("[readSimpleParam] claimed length = %d\n", length)

// 	if length < 0 || r.rpos+int(length) > r.rsize {
// 		fmt.Printf("[readSimpleParam] claimed length too big or negative: rpos=%d rsize=%d\n", r.rpos, r.rsize)
// 		return nil
// 	}

// 	buf := r.rbuf[r.rpos : r.rpos+int(length)]
// 	r.rpos += int(length)

// 	switch ti.TypeId {
// 	case typeNText:
// 		return decodeUcs2(buf)
// 	case typeText:
// 		return string(buf)
// 	default: // image
// 		return buf
// 	}
// }

// func readParamTypeInfo(r *tdsBuffer, typeId byte, c *cryptoMetadata, encoding msdsn.EncodeParameters) (res typeInfo) {
// 	res.TypeId = typeId
// 	switch typeId {
// 	case typeText, typeImage, typeNText, typeVariant:
// 		if r.rpos+4 > r.rsize {
// 			fmt.Printf("[readParamTypeInfo] not enough bytes for length prefix: rpos=%d, rsize=%d\n", r.rpos, r.rsize)
// 			return
// 		}

// 		// LONGLEN_TYPE
// 		res.Size = int(r.int32())
// 		fmt.Printf("[readParamTypeInfo] length prefix: %d (from rpos %d to %d)\n", res.Size, r.rpos, r.rsize)

// 		res.Collation = readCollation(r)
// 		fmt.Printf("[readParamTypeInfo] collation: %v\n", res.Collation)
// 		res.Reader = readLongLenTypeForRpcParam
// 		return
// 	default:
// 		return readTypeInfo(r, typeId, c, encoding)
// 	}
// }

// func readLongLenTypeForRpcParam(ti *typeInfo, r *tdsBuffer, _ *cryptoMetadata) interface{} {
// 	fmt.Printf("[readLongLenTypeForRpcParam] rpos before read = %d, rsize = %d\n", r.rpos, r.rsize)

// 	if r.rpos+4 > r.rsize {
// 		fmt.Printf("[readLongLenTypeForRpcParam] not enough bytes to read length (rpos=%d, rsize=%d)\n", r.rpos, r.rsize)
// 		return nil
// 	}

// 	buf := make([]byte, ti.Size)
// 	r.ReadFull(buf)

// 	switch ti.TypeId {
// 	case typeText:
// 		return decodeChar(ti.Collation, buf)
// 	case typeImage:
// 		return buf
// 	case typeNText:
// 		return decodeNChar(buf)
// 	default:
// 		badStreamPanicf("Invalid typeid")
// 	}
// 	panic("shoulnd't get here")
// }

// readParamTypeInfo parses TYPE_INFO specifically for RPC parameters.
// It handles the omission of TableName for legacy LOB types and assigns
// specific readers for them. For all other types, it delegates
// to the original readTypeInfo function.
func readParamTypeInfo(r *tdsBuffer, typeId byte, c *cryptoMetadata, encoding msdsn.EncodeParameters) (res typeInfo) {
	res.TypeId = typeId // Type ID was already read by the caller (parseParams)

	switch typeId {
	case typeNText:
		// Parse NTEXT metadata for parameters: Size (4b), Collation (5b). Skip TableName.
		// Check if buffer has enough space for Size + Collation
		if r.rpos+4+5 > r.rsize {
			badStreamPanicf("[readParamTypeInfo] NTEXT: not enough data for size/collation at pos %d (rsize %d)", r.rpos, r.rsize)
		}
		res.Size = int(r.int32())        // Read METADATA size (LONGLEN)
		res.Collation = readCollation(r) // Read METADATA collation
		// *** TableName is NOT read for parameters ***
		res.Reader = readNTextParamValue // Assign the NEW reader for parameter instance data
		return                           // Return directly

	case typeText:
		// Parse TEXT metadata for parameters: Size (4b), Collation (5b). Skip TableName.
		if r.rpos+4+5 > r.rsize { // Check for Size + Collation
			badStreamPanicf("[readParamTypeInfo] TEXT: not enough data for size/collation at pos %d (rsize %d)", r.rpos, r.rsize)
		}
		res.Size = int(r.int32())        // Read METADATA size (LONGLEN)
		res.Collation = readCollation(r) // Read METADATA collation
		// *** TableName is NOT read for parameters ***
		res.Reader = readTextParamValue // Assign the NEW reader for parameter instance data
		return                          // Return directly

	case typeImage:
		// Parse IMAGE metadata for parameters: Size (4b). Skip TableName.
		if r.rpos+4 > r.rsize { // Check for Size
			badStreamPanicf("[readParamTypeInfo] IMAGE: not enough data for size at pos %d (rsize %d)", r.rpos, r.rsize)
		}
		res.Size = int(r.int32()) // Read METADATA size (LONGLEN)
		// IMAGE has no Collation
		// *** TableName is NOT read for parameters ***
		res.Reader = readImageParamValue // Assign the NEW reader for parameter instance data
		return                           // Return directly

	default:
		// For all other types, delegate to the original library function.
		// This ensures correct handling for fixed types, numeric, dates,
		// PLP types (varchar(max) etc.), variant, UDTs, TVPs etc.

		// Call the original function (ensure it's accessible)
		// It will handle reading the rest of the metadata and assigning the correct original reader.
		return readTypeInfo(r, typeId, c, encoding) // Requires original readTypeInfo
	}
}

// readNTextParamValue reads an NTEXT parameter value assuming no TextPtr/Timestamp.
// It expects the stream format: DataLength (4 bytes) | TextData (variable)
func readNTextParamValue(ti *typeInfo, r *tdsBuffer, _ *cryptoMetadata) interface{} {
	// 1. Read Actual Data Length (LONGLEN / int32)
	// Check if buffer has enough space for the length prefix itself
	if r.rpos+4 > r.rsize {
		// Try reading the next packet first to ensure the length bytes are available
		_, err := r.BeginRead()
		if err != nil {
			// If BeginRead fails (e.g., connection closed), we can't proceed
			badStreamPanicf("Reading NTEXT param data: error fetching packet for length prefix: %v", err)
		}
		// Re-check after potentially reading a new packet
		if r.rpos+4 > r.rsize {
			badStreamPanicf("Reading NTEXT param data: not enough data for length prefix even after next packet at pos %d (rsize %d)", r.rpos, r.rsize)
		}
	}
	size := r.int32() // Read 4 bytes for the actual data length

	// 2. Handle NULL or Invalid Size
	if size == -1 {
		return nil // Return nil for NULL
	}
	if size < 0 {
		badStreamPanicf("Invalid NTEXT param data size: %d", size)
	}
	if size == 0 {
		return "" // Return empty string for zero-length NTEXT
	}

	// 3. Allocate buffer
	// Add a sanity check for extremely large sizes if needed
	// if size > MAX_REASONABLE_LOB_SIZE { badStreamPanicf(...) }
	ti.Buffer = make([]byte, size) // Store the buffer in typeInfo for later use

	// 4. Read the actual data using tdsBuffer.ReadFull (handles multi-packet)
	r.ReadFull(ti.Buffer) // ReadFull internally calls BeginRead when needed

	// 5. Decode the buffer (assuming decodeNChar handles UCS-2/UTF-16LE)
	// NOTE: Ensure `decodeNChar` function is accessible/correctly implemented.
	return decodeNChar(ti.Buffer)
}

// readTextParamValue reads a TEXT parameter value assuming no TextPtr/Timestamp.
// It expects the stream format: DataLength (4 bytes) | TextData (variable)
func readTextParamValue(ti *typeInfo, r *tdsBuffer, _ *cryptoMetadata) interface{} {
	// 1. Read Actual Data Length (LONGLEN / int32)
	if r.rpos+4 > r.rsize {
		_, err := r.BeginRead()
		if err != nil {
			badStreamPanicf("Reading TEXT param data: error fetching packet for length prefix: %v", err)
		}
		if r.rpos+4 > r.rsize {
			badStreamPanicf("Reading TEXT param data: not enough data for length prefix even after next packet at pos %d (rsize %d)", r.rpos, r.rsize)
		}
	}
	size := r.int32()

	// 2. Handle NULL or Invalid Size
	if size == -1 {
		return nil
	}
	if size < 0 {
		badStreamPanicf("Invalid TEXT param data size: %d", size)
	}
	if size == 0 {
		return ""
	}

	// 3. Allocate buffer
	ti.Buffer = make([]byte, size) // Store the buffer in typeInfo for later use

	// 4. Read the actual data using tdsBuffer.ReadFull
	r.ReadFull(ti.Buffer)

	// 5. Decode the buffer using collation stored in ti
	// NOTE: Ensure `decodeChar` and `ti.Collation` are accessible/correct.
	return decodeChar(ti.Collation, ti.Buffer)
}

// readImageParamValue reads an IMAGE parameter value assuming no TextPtr/Timestamp.
// It expects the stream format: DataLength (4 bytes) | TextData (variable)
func readImageParamValue(ti *typeInfo, r *tdsBuffer, _ *cryptoMetadata) interface{} {
	// 1. Read Actual Data Length (LONGLEN / int32)
	if r.rpos+4 > r.rsize {
		_, err := r.BeginRead()
		if err != nil {
			badStreamPanicf("Reading IMAGE param data: error fetching packet for length prefix: %v", err)
		}
		if r.rpos+4 > r.rsize {
			badStreamPanicf("Reading IMAGE param data: not enough data for length prefix even after next packet at pos %d (rsize %d)", r.rpos, r.rsize)
		}
	}
	size := r.int32()

	// 2. Handle NULL or Invalid Size
	if size == -1 {
		return nil
	}
	if size < 0 {
		badStreamPanicf("Invalid IMAGE param data size: %d", size)
	}
	if size == 0 {
		return []byte{}
	} // Return empty byte slice

	// 3. Allocate buffer
	buf := make([]byte, size)

	// 4. Read the actual data using tdsBuffer.ReadFull
	r.ReadFull(buf)

	// 5. Return raw bytes
	return buf
}
