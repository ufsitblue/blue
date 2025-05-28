# ISP
Do you want to be an ISP and provide all types of self-hosted services for
your customers? Then you've come to the right place!

All software used here is free and open source.

> "Another win for the open-source community!"
> -- Me

## Considerations
Please make sure the following ports are open on the firewall:
 - 20401
 - 20402
 - 20403
 - 20404
 - 20501 - Planka
 - 20502 - Uptime-Kuma
 - 20503 - NTFY
 - 20504 - Caddy

If you want to be extra secure, you should firewall off the following ports,
which will be opened by the services contained within:
 - 1337
 - 3000
 - 3001
 - 5432
 - 8000
 - 8080
 - 45411 - Caddy
 - 45412 - Caddy
