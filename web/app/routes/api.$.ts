import type {ActionFunctionArgs, LoaderFunctionArgs} from 'react-router'

import app from '@/api'

export async function action({request}: ActionFunctionArgs) {
  return app.fetch(request)
}
export async function loader({request}: LoaderFunctionArgs) {
  return app.fetch(request)
}
