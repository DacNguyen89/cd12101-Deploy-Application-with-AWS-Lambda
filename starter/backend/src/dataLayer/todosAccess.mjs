import { DynamoDB } from '@aws-sdk/client-dynamodb'
import { DynamoDBDocument } from '@aws-sdk/lib-dynamodb'
import AWSXRay from 'aws-xray-sdk-core'
import { logger } from '../utils/logger.mjs'

export class TodoAccess {
  constructor(
    documentClient = AWSXRay.captureAWSv3Client(new DynamoDB()),
    todosTable = process.env.TODOS_TABLE
  ) {
    this.documentClient = documentClient
    this.todosTable = todosTable
    this.dynamoDbClient = DynamoDBDocument.from(this.documentClient, {
      marshallOptions: {
        removeUndefinedValues: true
      }
    })
  }

  async getAllTodos(userId) {
    logger.info('Getting all todos')
    const result = await this.dynamoDbClient.query({
      TableName: this.todosTable,
      KeyConditionExpression: 'userId = :userId',
      ExpressionAttributeValues: {
        ':userId': userId
      }
    })
    return result.Items
  }

  async createTodo(todo) {
    logger.info(`Creating a todo with todoId ${todo.todoId}`)

    await this.dynamoDbClient.put({
      TableName: this.todosTable,
      Item: todo
    })

    return todo
  }

  async deleteTodo(todoId, userId) {
    logger.info(`Deleting a todo with todoId ${todoId}`)

    await this.dynamoDbClient.delete({
      TableName: this.todosTable,
      Key: { todoId, userId }
    })
  }

  async updateTodo(todoId, todo, userId) {
    logger.info(`Update a todo with todoId ${todoId}`)

    await this.dynamoDbClient.update({
      TableName: this.todosTable,
      Key: { todoId, userId },
      // Item: todo,
      UpdateExpression: 'set name = :n, dueDate = :due, done = :dn',
      ConditionExpression: 'attribute_exists(todoId)',
      ExpressionAttributeValues: {
        ':n': todo.name,
        ':due': todo.dueDate,
        ':dn': todo.done
      }
    })
  }

  async saveImageUrl(todoId, userId) {
    const bucketName = process.env.IMAGE_S3_BUCKET
    await this.dynamoDbClient.update({
      TableName: this.todosTable,
      Key: { userId, todoId },
      ConditionExpression: 'attribute_exists(todoId)',
      UpdateExpression: 'set attachmentUrl = :attachmentUrl',
      ExpressionAttributeValues: {
        ':attachmentUrl': `https://${bucketName}.s3.amazonaws.com/${todoId}`
      }
    })
  }
}
