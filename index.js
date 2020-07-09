const { Plugin } = require('powercord/entities')
const { get } = require('powercord/http')

module.exports = class SiteCheck extends Plugin {
    startPlugin() {
        powercord.api.commands.registerCommand({
            aliases: ['checkurl'],
            command: 'checksite',
            description: 'Checks website security via sitecheck.sucuri.net.',
            usage: '{c} <site>',
            executor: async args => {
                if (!args[0]) return { result: 'Provide site to check.' }

                const req = await get('https://sitecheck.sucuri.net/api/v3/').query('scan', args[0])
                if (req.statusCode != 200) return { result: 'Something went wrong :(' }
                const { body } = req

                if (body.scan.error) return { result: body.scan.error }
                const r = { result: {
                    title: `Website scan: ${body.site.input}`,
                    description: `Rating: **${body.ratings.total.rating}**`,
                    fields: [
                        {
                            name: 'Ratings',
                            value: Object.keys(body.ratings).filter(r => r != 'total').map(r =>
                                `${r == 'tls' ? 'TLS' : r[0].toUpperCase() + r.slice(1)} (${body.ratings[r].passed}): **${body.ratings[r].rating}**`)
                                .join('\n'),
                            inline: true
                        }
                    ],
                    type: 'rich'
                }}
                if (body.site.redirects_to) r.result.fields.push({
                    name: 'Redirects',
                    value: body.site.redirects_to.join('\n'),
                    inline: true
                })
                let runningOn = body.site.running_on.join('\n')
                if (Object.keys(body.software).length > 1) {
                    runningOn += '\n\n**Additional software**:\n'
                    Object.keys(body.software).filter(k => k != 'server').forEach(k => {
                        runningOn += `${k.replace(/_/g, ' ')}: ${body.software[k].map(s => `${s.name} ${s.version || ''}`).join(', ')}\n`
                    })
                }
                r.result.fields.push(
                    {
                        name: 'Running on',
                        value: runningOn,
                        inline: true
                    },
                    {
                        name: 'IP',
                        value: body.site.ip.join('\n'),
                        inline: true
                    }
                )
                if (body.blacklists) r.result.fields.push({
                    name: 'Blacklists',
                    value: body.blacklists.map(b => `Blacklisted by ${b.vendor}. [Info](${b.info_url})`).join('\n')
                })

                switch (body.ratings.total.rating) {
                    case 'A':
                    case 'B':
                        r.result.color = 0x609f43
                        break
                    case 'C':
                        r.result.color = 0xffa200
                        break
                    case 'D':
                    case 'E':
                        r.result.color = 0xf2462c
                        break
                }

                if (body.recommendations || body.warnings) {
                    const field = {
                        name: 'Warnings',
                        value: ''
                    },
                    tls = body.recommendations && body.recommendations.tls_major,
                    s = body.recommendations && body.recommendations.security_major,
                    outdated = body.warnings && body.warnings.outdated,
                    issues = body.warnings && body.warnings.site_issues
                    if (tls) {
                        field.value += '**TLS**:\n'
                        Object.keys(tls).forEach(r => {
                            switch (r) {
                                case 'http_credit_card':
                                    field.value += '- Credit card input field detected on an unencrypted HTTP page.\n'
                                    break
                                case 'http_password':
                                    field.value += '- Password input field detected on an unencrypted HTTP page.\n'
                                    break
                                case 'no_https':
                                    field.value += '- HTTPS version of this website is not accessible\n'
                                    break
                                case 'no_redirect_to_https':
                                    field.value += '- No redirect from HTTP to HTTPS found.\n'
                                    break
                                case 'mixed_content':
                                    field.value += '- HTTPS mixed content found.\n'
                                    break
                                case '3des_cipher':
                                    field.value += '- Triple-DES cipher is vulnerable and insecure.\n'
                                    break
                                case 'tls_10':
                                case 'tls_11':
                                    field.value += '- TLS 1.0/1.1 are obsolete.\n'
                                    break
                                case 'sha1_intermediate':
                                    field.value += '- SHA-1 signature detected on an intermediate certificate.\n'
                                    break
                            }
                        })
                    }
                    if (s) {
                        field.value += '**Security**:\n'
                        Object.keys(s).forEach(r => {
                            switch (r) {
                                case 'directory_listing_enabled':
                                    field.value += '- Directory Listing is enabled. This can lead to information leakage.\n'
                                    break
                                case 'git_visible':
                                    field.value += '- Git directory is publicly accessible. This can lead to information leakage.\n'
                                    break
                                case 'trace_method':
                                    field.value += '- HTTP Trace Method is allowed.\n'
                                    break
                            }
                        })
                    }
                    if (outdated) field.value += `**Outdated**:\n${outdated.map(s => `- ${s.name} under ${s.safe_version} (${s.version})`).join('\n')}\n`
                    if (issues) field.value += `**Site Issues**:\n${issues.map(i => `- ${i.msg} (${i.location})`)}\n`
                    if (field.value != '') r.result.fields.push(field)
                }
                return r
            }
        })
    }

    pluginWillUnload() {
        powercord.api.commands.unregisterCommand('checksite')
    }
}
