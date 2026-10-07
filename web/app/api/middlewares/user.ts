import {Elysia} from 'elysia'

import {user_from_headers} from '@/helpers/user.server'

export default new Elysia().derive({as: 'scoped'}, ({request, status}) => {
  const user = user_from_headers(request.headers)
  if (user === null) throw status(401)

  return {user}
})
