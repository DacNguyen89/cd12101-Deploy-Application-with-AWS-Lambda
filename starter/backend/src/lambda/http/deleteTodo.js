import middy from '@middy/core'
import cors from '@middy/http-cors'
import httpErrorHandler from '@middy/http-error-handler'
import { deleteTodo } from '../../businessLogic/todos.mjs'
import { getUserId } from '../../auth/utils.mjs'
import { logger } from '../../utils/logger.mjs'

export const handler = middy()
  .use(httpErrorHandler())
  .use(
    cors({
      credentials: true
    })
  )
  .handler(async (event) => {
    logger.info('Processing event: ', event)

    const todoId = event.pathParameters.todoId
    const authorization = event.headers.Authorization
    const userId = getUserId(authorization)

    await deleteTodo(todoId, userId)

    return {
      statusCode: 204
    }
  })
