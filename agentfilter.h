struct ssh;
struct Channel;

/* If configured, apply a filter to an agent forwarding channel. */
void	agent_filter_maybe_initialize(struct ssh *ssh, const struct Channel *c);
