package io.nekohasekai.sfa.utils

import io.nekohasekai.libbox.Libbox
import kotlinx.serialization.json.*
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Base64

object VlessSubscriptionParser {

    private data class Node(
        val tag: String,
        val json: JsonObject
    )

    fun normalize(content: String): String {
        val raw = content.removePrefix("\uFEFF").trim()

        // Keep an already valid sing-box configuration unchanged.
        try {
            Libbox.checkConfig(raw)
            return raw
        } catch (_: Exception) {
        }

        val candidates = mutableListOf(raw)

        val compact = raw.filterNot { it.isWhitespace() }
        val padded = compact + "=".repeat((4 - compact.length % 4) % 4)

        for (decoder in listOf(
            Base64.getDecoder(),
            Base64.getUrlDecoder(),
            Base64.getMimeDecoder()
        )) {
            try {
                val decoded = String(
                    decoder.decode(padded),
                    StandardCharsets.UTF_8
                ).trim()

                if (decoded.isNotEmpty()) candidates.add(decoded)
            } catch (_: Exception) {
            }
        }

        val links = linkedSetOf<String>()

        for (candidate in candidates) {
            Regex("""vless://[^\s"'<>]+""", RegexOption.IGNORE_CASE)
                .findAll(candidate)
                .forEach { links.add(it.value.trimEnd(',', ';')) }
        }

        if (links.isEmpty()) {
            throw IllegalArgumentException(
                "No VLESS links found. Check the subscription address or content."
            )
        }

        val nodes = mutableListOf<Node>()

        for (link in links) {
            try {
                nodes.add(parseLink(link, nodes.size + 1))
            } catch (_: Exception) {
                // Ignore invalid subscription entries.
            }
        }

        if (nodes.isEmpty()) {
            throw IllegalArgumentException("No valid VLESS servers found.")
        }

        val tags = nodes.map { it.tag }

        val config = buildJsonObject {
            putJsonObject("log") {
                put("level", "warn")
            }

            putJsonObject("dns") {
                putJsonArray("servers") {
                    add(buildJsonObject {
                        put("type", "udp")
                        put("tag", "dns-remote")
                        put("server", "1.1.1.1")
                    })
                }
                put("final", "dns-remote")
            }

            putJsonArray("inbounds") {
                add(buildJsonObject {
                    put("type", "tun")
                    put("tag", "tun-in")
                    putJsonArray("address") {
                        add("172.19.0.1/30")
                    }
                    put("auto_route", true)
                    put("strict_route", true)
                })
            }

            putJsonArray("outbounds") {
                nodes.forEach { add(it.json) }

                add(buildJsonObject {
                    put("type", "urltest")
                    put("tag", "auto")
                    putJsonArray("outbounds") {
                        tags.forEach { add(it) }
                    }
                    put("url", "https://www.gstatic.com/generate_204")
                    put("interval", "3m")
                    put("tolerance", 50)
                })

                add(buildJsonObject {
                    put("type", "selector")
                    put("tag", "proxy")
                    putJsonArray("outbounds") {
                        add("auto")
                        tags.forEach { add(it) }
                    }
                    put("default", "auto")
                })

                add(buildJsonObject {
                    put("type", "direct")
                    put("tag", "direct")
                })
            }

            putJsonObject("route") {
                put("auto_detect_interface", true)
                put("final", "proxy")
            }
        }

        val result = Json.encodeToString(config)
        Libbox.checkConfig(result)
        return result
    }

    private fun parseLink(link: String, index: Int): Node {
        val uri = URI(link)
        val uuid = uri.userInfo
            ?: throw IllegalArgumentException("Missing UUID")

        val host = uri.host
            ?: throw IllegalArgumentException("Missing server")

        val port = uri.port
        if (port !in 1..65535) {
            throw IllegalArgumentException("Invalid port")
        }

        val params = mutableMapOf<String, String>()

        uri.rawQuery?.split("&")?.forEach { item ->
            val parts = item.split("=", limit = 2)
            val key = decode(parts[0])
            val value = if (parts.size > 1) decode(parts[1]) else ""
            params[key] = value
        }

        val name = decode(uri.rawFragment ?: "").ifBlank {
            "VLESS $index"
        }.take(60)

        val tag = name
            .replace(Regex("[^A-Za-z0-9_\\- ]"), "")
            .trim()
            .ifBlank { "VLESS $index" }
            .let { "$it-$index" }

        val security = params["security"] ?: "none"

        val node = buildJsonObject {
            put("type", "vless")
            put("tag", tag)
            put("server", host)
            put("server_port", port)
            put("uuid", uuid)

            params["flow"]?.takeIf { it.isNotBlank() }?.let {
                put("flow", it)
            }

            if (security == "tls" || security == "reality") {
                putJsonObject("tls") {
                    put("enabled", true)

                    params["sni"]?.takeIf { it.isNotBlank() }?.let {
                        put("server_name", it)
                    }

                    params["fp"]?.takeIf { it.isNotBlank() }?.let {
                        putJsonObject("utls") {
                            put("enabled", true)
                            put("fingerprint", it)
                        }
                    }

                    if (security == "reality") {
                        putJsonObject("reality") {
                            put("enabled", true)
                            params["pbk"]?.let { put("public_key", it) }
                            params["sid"]?.let { put("short_id", it) }
                        }
                    }

                    params["alpn"]?.takeIf { it.isNotBlank() }?.let { value ->
                        putJsonArray("alpn") {
                            value.split(",").forEach { add(it) }
                        }
                    }
                }
            }

            val transport = params["type"] ?: "tcp"

            if (transport == "ws") {
                putJsonObject("transport") {
                    put("type", "ws")
                    params["path"]?.let { put("path", it) }

                    params["host"]?.takeIf { it.isNotBlank() }?.let {
                        putJsonObject("headers") {
                            put("Host", it)
                        }
                    }
                }
            } else if (transport == "grpc") {
                putJsonObject("transport") {
                    put("type", "grpc")
                    params["serviceName"]?.let {
                        put("service_name", it)
                    }
                }
            } else if (transport == "httpupgrade") {
                putJsonObject("transport") {
                    put("type", "httpupgrade")
                    params["path"]?.let { put("path", it) }
                    params["host"]?.let { put("host", it) }
                }
            }
        }

        return Node(tag, node)
    }

    private fun decode(value: String): String {
        return URLDecoder.decode(value, "UTF-8")
    }
}
