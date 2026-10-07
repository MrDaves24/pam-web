import {Elysia} from 'elysia'

import authorization from './endpoints/authorization'

const app = new Elysia({prefix: '/api'})
    .all('*', ({request, path}) => {
    console.info(`404 on ${request.method} '${path}'`)
  })
  .onRequest(({request}) => {
    console.debug('New request')
    console.debug(`${request.method} ${request.url}`)
  })
  .onError(({code, error}) => {
    console.debug('An error occurred')
    console.debug(`code : ${code}`)
    console.debug('error :', error)
  })

  .get('/health', () => console.debug('healthcheck'))

  .use(authorization)

  .compile()

export default app
export type api = typeof app
