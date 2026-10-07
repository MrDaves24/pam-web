import {treaty} from '@elysiajs/eden'
import type {api} from '.'

// Don't follow redirects : an expired Authelia session redirects to its login (another site), the page reloads instead
export default treaty<api>(`${window.location.protocol}//${window.location.host}`, {fetch: {redirect: 'manual'}}).api
