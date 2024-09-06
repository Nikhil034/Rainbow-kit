const { DB_USERNAME, DB_PASSWORD } = process.env;

export const connectionStr = `mongodb+srv://${DB_USERNAME}:${DB_PASSWORD}@cluster0.qkgxzxw.mongodb.net/Sample_db?retryWrites=true&w=majority`;