import { serve } from '@hono/node-server'
import app from './worker/index'

const port = Number(process.env.PORT) || 3000

console.log(`Server is running on port ${port}`)

serve({
  fetch: (request) => {
    return app.fetch(request, process.env as any)
  },
  port
})
