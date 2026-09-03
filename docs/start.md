---
layout: default
title: Start here
section: start
description: Set up a fresh Boetticher lab, then settle into the day-to-day rhythm.
---

# Start with a fresh host and a cup of something good

Boetticher starts from a fresh, supported Proxmox VE installation on amd64 hardware. You will also need a macOS or Linux controller with the Boetticher binary, SSH, and Ansible Core; the current HOME-side address for Proxmox; its root CA certificate; and a private place for your site directory.

The default virtual-only setup needs one Ethernet port. Version 0.5.0 does not remove or renumber any VLANs, and it does not ask you to reconfigure the switch for a normal fresh install. A physical VLAN trunk or an external firewall needs a second port and a VLAN-aware switch when you are ready for that bigger experiment.

The 0.5.0 rhythm is pleasantly deliberate: import the signed release bundle,
make a live plan, deploy the exact digest you reviewed, then check the lab.
StreamDeck is now an external companion-Pi capability, so a new install does
not create a StreamDeck guest in Proxmox.

## The happy path

Replace <code>PROXMOX_HOME_IP</code> and the certificate path with your real values. The HOME address is the one your existing router gave Proxmox; it is not a new lab address.

```text
boetticher init --site-dir my-boetticher
boetticher bootstrap-endpoint set PROXMOX_HOME_IP --site my-boetticher
boetticher preflight --site my-boetticher --live
boetticher bootstrap --site my-boetticher --recovery-confirmed --proxmox-ca /path/to/pve-root-ca.pem
boetticher bundle import ./boetticher-0.5.0.tar.gz --site my-boetticher
boetticher plan --site my-boetticher --live --json
boetticher deploy --plan sha256:PLAN_DIGEST --site my-boetticher
boetticher status --site my-boetticher --live
```

`init` makes your little private site repository and its age recovery identity. Keep an independent copy of that identity somewhere sensible before you need it. If you choose the dedicated-data storage profile, pause at the confirmation and make sure the selected disk really is the spare one.

<aside class="callout">
  <p><strong>Bring your own firewall?</strong> Add <code>--external-firewall</code> to <code>init</code>, then select and record the physical trunk explicitly during live preflight and bootstrap:</p>
  <pre><code>boetticher preflight --site my-boetticher --live --record --trunk-interface IFACE
boetticher bootstrap --site my-boetticher --recovery-confirmed --proxmox-ca /path/to/pve-root-ca.pem --trunk-interface IFACE</code></pre>
  <p>Your appliance must provide the six VLANs, gateway addresses, DHCP where applicable, DNS/NTP routes, NAT, and zone separation. That is a proper architectural handoff, not a cosmetic setting; the <a href="lab.html#when-you-want-to-go-bigger">lab guide</a> has the compact contract.</p>
</aside>

## Your everyday rhythm

Once the lab is up, the regular loop stays boring in the best possible way:

```text
boetticher plan --site ./my-boetticher --live --json
boetticher deploy --plan sha256:PLAN_DIGEST --site ./my-boetticher
boetticher status --site ./my-boetticher --live
boetticher doctor --site ./my-boetticher --live
```

Without <code>--live</code>, a command reads the site directory on your controller. With it, the command also asks the running lab what is happening. <code>status --live</code> is the quick “is the lab okay?” view; <code>doctor --live</code> is the useful “what should I do next?” companion.

To add something new, configure it first and deploy when you like the plan:

```text
boetticher module list --site ./my-boetticher
boetticher module configure gatus --site ./my-boetticher
boetticher plan --site ./my-boetticher --live --json
boetticher deploy --plan sha256:PLAN_DIGEST --site ./my-boetticher
```

Configuration changes stay in the site until you explicitly deploy them. Use
`--dry-run` when you would like a preview without saving anything.

The [modules guide](modules.html) is where the interesting extras live. The [command menu](commands.html) is there whenever a flag escapes your brain.

## If the first run gets a little weird

Start with the final line from the command that stopped, then work the small ladder:

1. `boetticher status --site ./my-boetticher --live`
2. `boetticher doctor --site ./my-boetticher --live`
3. `boetticher plan --site ./my-boetticher --live --json`
4. Fix the one thing it calls out, refresh the plan, then deploy with its digest.

For a changed Proxmox HOME address, use the address you already know:

```text
boetticher bootstrap-endpoint set PROXMOX_HOME_IP --site ./my-boetticher
boetticher preflight --site ./my-boetticher --live
```

No range scans, no panic cleanup, no ritual sacrifice of a VM. The [lab guide](lab.html#recovery-without-drama) covers the calm recovery order for storage, DNS, a missing platform guest, or a lost age identity.
