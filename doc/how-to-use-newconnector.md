# How to use the Connector object

A Connector holds information in a DSN and is ready to make a new connection at any time. Connector implements the database/sql/driver connector interface so it can be passed to the database/sql `OpenDB` function. Settings that cannot be passed through a DSN string can be set directly on the connector by using the `SessionInitSQL` member of the Connector.

To use the Connector type, first you need to import the sql and go-mssqldb package

```
import (
  "database/sql"
  mssqldb "github.com/denisenkom/go-mssqldb"`
)
```

Now you can create a Connector object by calling `NewConnector`, which creates a new connector from a DSN.

```
dsn := "sqlserver://username:password@hostname/instance?database=databasename"
connector, err := mssql.NewConnector(dsn)
```

You can set `connector.SessionInitSQL` for any options that cannot be passed through in the dsn string.

`connector.SessionInitSQL = "SET ANSI_NULLS ON"`

Open a database by passing connector to `sql.OpenDB`.

`db := sql.OpenDB(connector)`

The returned DB maintains its own pool of idle connections. Now you can use you `sql.DB` object for querying and executing queries.