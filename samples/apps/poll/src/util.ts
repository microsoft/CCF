// For unit testing / demo purposes only, as it is hard
// to use many real identities.
const FAKE_TOKEN_PREFIX = 'user='

export function parseAuthToken(authHeader: string): string {
    const parts = authHeader.split(' ', 2)
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
        throw new Error('unexpected authorization type')
    }
    const token = parts[1]
    if (token.startsWith(FAKE_TOKEN_PREFIX)) {
        const user = token.substr(FAKE_TOKEN_PREFIX.length)
        if (user.length == 0) {
            throw new Error('empty user not allowed')
        }
        return user
    }
    // parse JWT and return "sub"
    throw new Error('jwt parsing not implemented yet')
}
