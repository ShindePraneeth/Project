import { ApolloServer } from '@apollo/server';
import { startStandaloneServer } from '@apollo/server/standalone';
import jwt from 'jsonwebtoken';
import { promises as fs } from 'fs';
import bcrypt from 'bcrypt';

const SECRET_KEY = 'your_secret_key';
const PORT = 3001;

let users = [];
let transactions = [];

async function loadData() {
  try {
    const userData = await fs.readFile('user.json', 'utf8');
    users = JSON.parse(userData);
    
    // Hash passwords if they are not already hashed
    const saltRounds = 10;
    for (const user of users) {
      if (!user.password.startsWith('$2b$')) {
        user.password = await bcrypt.hash(user.password, saltRounds);
      }
    }
    // Save the updated user data back to the file
    await fs.writeFile('user.json', JSON.stringify(users, null, 2));
  } catch (error) {
    console.error('Error reading or hashing user data:', error);
    users = [];
  }

  try {
    const transactionData = await fs.readFile('transactions.json', 'utf8');
    transactions = JSON.parse(transactionData);
  } catch (error) {
    console.error('Error reading transaction data:', error);
    transactions = [];
  }
}

const typeDefs = `#graphql
  type User {
    id: ID!
    username: String!
    email: String!
  }

  type Transaction {
    id: ID!
    userId: ID!
    description: String!
    amount: Float!
    type: String!
    date: String!
  }

  type AuthPayload {
    token: String!
    user: User!
  }

  type Query {
    getTransactions: [Transaction!]!
  }

  type Mutation {
    register(username: String!, email: String!, password: String!): User!
    login(username: String!, password: String!): AuthPayload!
    addTransaction(description: String!, amount: Float!, type: String!, date: String!): Transaction!
    updateTransaction(id: ID!, description: String, amount: Float, type: String, date: String): Transaction!
    deleteTransaction(id: ID!): Boolean!
  }
`;

const resolvers = {
  Query: {
    getTransactions: (_, __, context) => {
      if (!context.user) throw new Error('Not authenticated');
      return transactions.filter(t => t.userId.toString() === context.user.id.toString());
    },
  },
  Mutation: {
    register: async (_, { username, email, password }) => {
      if (users.find(u => u.username === username)) {
        throw new Error('Username already exists');
      }
      if (users.find(u => u.email === email)) {
        throw new Error('Email already exists');
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const newUser = {
        id: (users.length + 1).toString(),
        username,
        email,
        password: hashedPassword
      };
      users.push(newUser);

      await fs.writeFile('user.json', JSON.stringify(users, null, 2));
      return newUser;
    },
    login: async (_, { username, password }) => {
      const user = users.find(u => u.username === username || u.email === username);
      if (!user || !(await bcrypt.compare(password, user.password))) {
        throw new Error('Invalid credentials');
      }

      const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '1h' });
      return { token, user };
    },
    addTransaction: (_, { description, amount, type, date }, context) => {
      if (!context.user) throw new Error('Not authenticated');
      const newTransaction = {
        id: (transactions.length + 1).toString(),
        userId: context.user.id,
        description,
        amount,
        type: type.toLowerCase(),
        date
      };
      transactions.push(newTransaction);
      fs.writeFile('transactions.json', JSON.stringify(transactions, null, 2));
      return newTransaction;
    },
    updateTransaction: (_, { id, ...updates }, context) => {
      if (!context.user) throw new Error('Not authenticated');
      const index = transactions.findIndex(t => t.id === id && t.userId === context.user.id);
      if (index === -1) throw new Error('Transaction not found or not authorized');

      transactions[index] = { ...transactions[index], ...updates };
      fs.writeFile('transactions.json', JSON.stringify(transactions, null, 2));
      return transactions[index];
    },
    deleteTransaction: (_, { id }, context) => {
      if (!context.user) throw new Error('Not authenticated');
      const index = transactions.findIndex(t => t.id === id && t.userId === context.user.id);
      if (index === -1) throw new Error('Transaction not found or not authorized');

      transactions.splice(index, 1);
      fs.writeFile('transactions.json', JSON.stringify(transactions, null, 2));
      return true;
    },
  },
};

async function startServer() {
  await loadData();

  const server = new ApolloServer({
    typeDefs,
    resolvers,
  });

  const { url } = await startStandaloneServer(server, {
    listen: { port: PORT },
    context: async ({ req }) => {
      const token = req.headers.authorization || '';
      if (token) {
        try {
          const decoded = jwt.verify(token.replace('Bearer ', ''), SECRET_KEY);
          const user = users.find(u => u.id === decoded.id);
          return { user };
        } catch (err) {
          console.error('Error verifying token:', err);
        }
      }
      return {};
    },
  });
  console.log(`🚀 Server ready at ${url}`);
}

startServer();
