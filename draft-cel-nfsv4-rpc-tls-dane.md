---
title: "Using RPC-with-TLS with DNS-Based Authentication of Named Entities"
abbrev: "RPC TLS with DANE"
category: std

docname: draft-cel-nfsv4-rpc-tls-dane-latest
submissiontype: IETF
ipr: trust200902
updates: 9289
stand_alone: yes
pi: [toc, sortrefs, symrefs, docmapping]
v: 3
area: "Web and Internet Transport"
workgroup: Network File System Version 4
keyword:
 - RPC
 - TLS
 - DANE
 - TLSA
 - DNSSEC
 - STRIPTLS

venue:
  group: nfsv4
  type: Working Group
  mail: nfsv4@ietf.org
  arch: https://mailarchive.ietf.org/arch/browse/nfsv4/
  github: chucklever/i-d-rpc-tls-dane
  latest: https://chucklever.github.io/i-d-rpc-tls-dane/draft-cel-nfsv4-rpc-tls-dane.html

author:
 -
    fullname: Charles Lever
    role: editor
    country: United States of America
    email: cel-ietf@chucklever.net

normative:
  RFC1035:
  RFC4033:
  RFC5280:
  RFC5531:
  RFC5890:
  RFC6066:
  RFC6698:
  RFC7671:
  RFC9289:
  RFC9525:
  RFC9846:

informative:
  RFC1833:
  RFC5011:
  RFC6125:
  RFC7250:
  RFC7258:
  RFC7435:
  RFC7672:
  RFC7942:
  RFC8881:
  RFC9076:
  I-D.ietf-dance-client-auth:

--- abstract

RPC-with-TLS assumes that DNS-Based Authentication of Named Entities
(DANE) is available on platforms where it is deployed, and recommends
that a client operating under an opportunistic security policy check
for a TLSA record before initiating an association, but does not say
how.  This document specifies the missing details, so that a TLSA
record authenticates an RPC server with no certification authority
trust anchor provisioned on the client.  It updates RFC 9289.


--- middle

# Introduction {#intro}

RPC-with-TLS {{RFC9289}} protects Remote Procedure Call {{RFC5531}}
traffic by encapsulating it in a TLS {{RFC9846}} session.  A client
discovers whether a server supports the mechanism by sending a NULL
procedure carrying the AUTH_TLS authentication flavor, in cleartext,
before the TLS handshake begins.  A server that supports RPC-with-TLS
replies with a "STARTTLS" token, after which the client sends a
ClientHello on the same connection or to the same UDP destination
port.

Section 5.2.1 of {{RFC9289}} requires every RPC-with-TLS implementation
to support authenticating server certificates by PKIX {{RFC5280}} trust.
A client that validates a server certificate checks a locally configured
expected DNS-ID against it.  The client resolves that name in the DNS to
reach the server, but the DNS supplies nothing that authenticates the
server or that says the server is expected to speak TLS.  Both facts
must be configured locally on every client.  Among the deployment
problems that follow from that, two stand out:

* Trust anchor distribution.  Deploying RPC-with-TLS at scale means
  provisioning every client with the certification authority material
  needed to validate the servers it will contact, and keeping that
  material current as certificates are issued and rotated.  A server
  operator who does not run or subscribe to a certification authority
  has no way to tell clients what key to expect other than by
  configuring each of them.

* STRIPTLS.  The AUTH_TLS probe and its reply are exchanged in
  cleartext.  An on-path attacker who suppresses the probe, or
  rewrites the reply so that it does not carry the "STARTTLS" token,
  can make a TLS-capable server appear not to support RPC-with-TLS.  A
  client under an opportunistic policy then proceeds in cleartext.
  Whether a client falls back or fails closed is decided by
  client-local policy alone; nothing the client learns on the way to
  the server tells it that TLS was expected.

{{RFC9289}} anticipated these problems and pointed at the same remedy
for them, DNS-Based Authentication of Named Entities (DANE)
{{RFC6698}}, in several places:

* Section 1 lists DNSSEC/DANE among the platform facilities that
  RPC-with-TLS support is assumed to build on.

* Section 6.1.1 offers two mitigations for STRIPTLS attacks, between
  which a client implementer may choose.  The first is a TLSA record,
  which "can alert clients that TLS is expected to work, and provide a
  binding of a hostname to the X.509 identity"; a client under an
  opportunistic security policy should check for the existence of such
  a record before initiating an association, and disconnects if TLS
  cannot be negotiated or authentication fails.  The second is a
  client security policy that requires a TLS session on every
  connection, which {{RFC9289}} strongly encourages where TLSA records
  are not available.

* Section 6.4 lists among its best security policy practices that,
  when using AUTH_NULL or AUTH_SYS, "both peers are RECOMMENDED to
  have DNSSEC TLSA records" together with "a security policy that
  requires mutual peer authentication and rejection of a connection
  when host authentication fails".

A TLSA RRset addresses both problems at once.  Published in a zone
the operator already signs, it carries the binding between a server
name and its public key in the DNS, alongside the name the client had
to resolve anyway, so no client needs certification authority
material for that server.  And because a DNSSEC-validated TLSA RRset
is an authenticated statement by the server operator that TLS is
expected to work, a client holding one can no longer treat silent
fallback to cleartext as acceptable: the STRIPTLS attack fails
closed.

However, {{RFC9289}} offers a sketch rather than a specification.  It
does not say enough for a client implementer to build DANE support
from it.  Two independent implementations reading Section 6.1.1 would
not interoperate, and neither would obtain the security property a
TLSA record appears to promise.

This document specifies DANE for RPC-with-TLS completely enough to
implement and to deploy.  The approach taken follows the operational
specifications for DANE developed in {{RFC7671}} and {{RFC7672}}.  Much
of what this document does is to make the RPC-specific choices that
those documents anticipate application protocols making.

## Scope {#scope}

This document defines client behavior and places no new requirements
on RPC servers beyond the publication requirement in {{rollover}};
{{deployment}} gives the operational guidance that accompanies it.
A server that conforms to {{RFC9289}} interoperates with a client
implementing this document without modification.

This document specifies the use of DANE to authenticate an RPC server
to an RPC client.  Authentication of an RPC client to an RPC server by
means of DANE is out of scope; see {{client-auth}}.

This document applies where the server authenticates itself with a
certificate.  A server association that uses the pre-shared key
mechanism of Section 5.2.2 of {{RFC9289}} presents no certificate for
DANE to authenticate. The procedures in this document do not apply to
it.

Section 5.1 of {{RFC7671}} also provides for matching a DANE-EE(3)
record with selector SPKI(1) against a raw public key {{RFC7250}}.
{{RFC9289}} defines no mechanism by which an RPC-with-TLS session
conveys a raw public key, so that case does not arise here.
Specifying one is work for a future document.

TLSA owner names are defined here for the transports {{RFC9289}}
itself defines, namely TLS over TCP and DTLS over UDP.  A future
document that specifies RPC over another transport is expected to
define the corresponding owner-name convention.

# Updates to RFC 9289 {#updates}

Section 1 of {{RFC9289}} assumes that DNSSEC and DANE are available
but does not specify their use.  This document specifies that use.
In doing so it changes {{RFC9289}} as set out in this section.

Two requirements of {{RFC9289}} are changed here:

* Section 5.2.1 of {{RFC9289}} requires PKIX path validation and a
  check of the expected DNS-ID or iPAddress subjectAltName against the
  presented certificate.  Those requirements continue to apply
  unchanged wherever this document requires PKIX authentication, and
  to the name checks performed for certificate usage DANE-TA(2).  They
  do not apply to a server authenticated by a DANE-EE(3) match, for
  the reasons given in Section 5.1 of {{RFC7671}} and restated in
  {{dane-ee}}.

* Where {{RFC9289}} cites {{RFC6125}} for certificate name checks,
  clients implementing this document perform those checks per
  {{RFC9525}}, which obsoletes {{RFC6125}}.  The additional
  restriction in Section 5.2.1 of {{RFC9289}}, that a DNS domain name
  in an RPC-with-TLS certificate contain no wildcard character, is
  retained.

Elsewhere {{RFC9289}} makes a recommendation or leaves a choice to
local policy.  This document replaces each of the following with a
requirement stated in the section named:

* The first bullet of Section 6.1.1 of {{RFC9289}} recommends a TLSA
  check before an association is initiated, and disconnection when
  TLS or authentication then fails.  {{lookup}}, {{behavior}}, and
  {{floor}} replace that recommendation.
  The check is meaningful only if the answer is DNSSEC-validated, and
  this document states what a client concludes from each outcome
  rather than from a record's presence alone.

* The second bullet of Section 6.1.1 and Section 6.4 of {{RFC9289}}
  recommend a policy that requires TLS and rejects a connection when
  host authentication fails.  {{floor}} and {{fallback}} require that
  behavior where this document pins a security floor.  Where no floor is pinned, {{fallback}} is weaker,
  since it permits cleartext operation when the server returns a
  well-formed decline.  A deployment that adopts either recommendation
  in full is more restrictive than {{fallback}} requires and remains
  conformant to this document.

* Section 4.1 of {{RFC9289}} leaves to local policy whether RPC
  operation continues in cleartext when the AUTH_TLS probe does not
  yield the "STARTTLS" indication.  {{fallback}} specifies that
  policy, and it is more restrictive than what {{RFC9289}} permits.

This document also extends the audit log that Section 6.1 of
{{RFC9289}} requires: {{audit}} adds to the required content of that
log and permits it to be assembled from correlatable events.

Nothing in this document changes the TLS version, ALPN, cipher suite,
confidentiality, or transport requirements of {{RFC9289}}, nor its
provisions for pre-shared keys or for RPCSEC_GSS.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document assumes a working knowledge of RPC version 2
{{RFC5531}}, of RPC-with-TLS {{RFC9289}}, and of DANE {{RFC6698}}
{{RFC7671}}.  It uses the DNSSEC validation states "secure",
"insecure", "bogus", and "indeterminate" as defined in Section 5 of
{{RFC4033}}.

The following terms are used as defined here.

Reference name:
: The DNS domain name by which the client selected the server it is
  contacting.  In practice this is the name that appeared in the
  administrative configuration that caused the association to be
  established -- for NFS, the server component of the mount
  specification.  {{refname}} states the requirements on it.

TLSA base domain:
: The domain name to which the port and transport labels are
  prepended to form a TLSA owner name, as in Section 3 of
  {{RFC6698}}.  A client may have more than one candidate base domain
  for a single reference name; see {{candidates}}.

Selected TLSA base domain:
: The candidate TLSA base domain whose evaluation produced the DNS
  outcome class for the association attempt.  See {{selected}}.

DNS outcome class:
: One of the five results defined in {{outcomes}} that a client
  assigns to a TLSA lookup for a given reference name, port, and
  transport.

Usable record:
: A TLSA record that the client is able to use to authenticate a
  server certificate, in the sense of Section 4.1 of {{RFC6698}} and
  as further constrained by {{usable}}.

Server association:
: The set of transport connections a client operates toward one
  server, selected by one reference name, and treated by the client as
  a single administrative and security unit.  {{RFC9289}} uses the
  term "association" informally; this document uses "server
  association" whenever the distinction from a single connection
  matters.  In NFS terms, a server association is what a single mount
  point, together with any additional connections established for it,
  is carried over.

Association attempt:
: One attempt by a client to establish a transport connection for a
  server association, from the selection of a destination through
  either the completion of a TLS handshake, a decision to proceed in
  cleartext, or failure.

Security floor:
: The minimum acceptable security level that a client has determined
  for a server association, and below which it MUST NOT operate.  See
  {{floor}}.

DANE policy mode:
: The client's configured disposition toward DANE for a given server
  association: disabled, opportunistic, or mandatory.  See {{modes}}.

# Overview of Operation {#overview}

A client that has DANE enabled for a server association performs, in
addition to what {{RFC9289}} already specifies, the following steps.

1. It derives a reference name for the server it is about to contact,
   subject to the requirements in {{refname}}.  A destination the
   client cannot name in the DNS, such as one selected by IP address
   literal, carries no DANE binding and is handled per {{no-dane}}.

2. It looks up TLSA records at the owner names derived from that
   reference name, the destination port, and the transport, and
   reduces the results to a single DNS outcome class.  {{lookup}}
   specifies this procedure.

3. It applies the outcome class to the association attempt.  A secure
   outcome pins a security floor for the association ({{floor}}),
   which constrains whether cleartext operation remains permissible
   and which failures are recoverable.

4. If a TLS handshake takes place, it authenticates the server
   according to the outcome class: by DANE ({{authn}}) where the
   client found a usable record, and by the PKIX rules of
   Section 5.2.1 of {{RFC9289}} otherwise.

5. It records the policy inputs, the decision, and the authentication
   result in the audit log that Section 6.1 of {{RFC9289}} already
   requires ({{audit}}).

Steps 2 and 3 concern the association attempt as a whole and can
therefore be performed before the AUTH_TLS probe is sent; step 4
necessarily happens during the handshake.  This document does not
specify how an implementation divides the work, only what a conforming
client concludes.  {{coherence}} states the two constraints that a
division of labor MUST respect.

## DANE policy modes {#modes}

A client implementing this document MUST support the following three
policy modes, and MUST allow the mode to be configured independently
for each server association.

Disabled:
: The client performs none of the procedures in this document.  Its
  behavior is that specified by {{RFC9289}}.

Opportunistic:
: The client performs the procedures in this document.  A DNS outcome
  class of SECURE_USABLE or SECURE_UNUSABLE pins a security floor and
  constrains the association as specified in {{behavior}} and
  {{floor}}.  Outcome classes that establish no floor leave the
  association attempt subject to {{RFC9289}} unchanged.  This mode is
  intended for fleet-wide deployment against a server population that
  has not uniformly published TLSA records; see {{adaptive}}.

Mandatory:
: The client performs the procedures in this document and additionally
  requires that the server be authenticated by DANE.  Any outcome
  other than SECURE_USABLE followed by a successful DANE
  authentication MUST fail the association attempt.  A destination
  that cannot carry a DANE binding at all ({{no-dane}}) fails rather
  than falling back to PKIX.

Mandatory mode never silently degrades to another mode.  In
particular, an implementation that has not implemented some part of
this specification -- a transport for which it defines no owner name,
a certificate usage it does not support -- MUST fail an association
attempt made in mandatory mode rather than proceed without the
protection the mode was configured to obtain.

# TLSA Records for RPC Services {#records}

## Owner names {#owner-names}

TLSA owner names for RPC services follow the convention in Section 3
of {{RFC6698}} without modification.  The owner name is formed by
prepending, to a TLSA base domain:

* the second label "_tcp" for RPC-with-TLS over TCP, or "_udp" for
  RPC-with-DTLS over UDP, per Sections 5.1.1 and 5.1.2 of
  {{RFC9289}}; and

* the first label, consisting of an underscore followed by the decimal
  representation, without leading zeros, of the port number to which
  the client connects.

For example, an NFS server reached at "nfs.example.com" on the default
NFS port over TCP publishes its TLSA RRset at
"_2049._tcp.nfs.example.com".

## Alternate ports {#ports}

The port in the owner name is the port to which the client actually
connects, not a registered port for the RPC program in use.  RPC
services are routinely offered on other ports, by site convention or
by local configuration: a service reached on port 20490 over TCP at
"nfs.example.com" publishes its TLSA RRset at
"_20490._tcp.nfs.example.com", and a server that offers the same
service on several ports publishes one TLSA RRset per port.

Because the port is part of the owner name, a TLSA RRset authenticates
the server at a known port and says nothing about the same server at
another port, in the same way that Section 4.1 of {{RFC9289}} observes
that a successful AUTH_TLS probe on one port and transport implies
nothing about any other.

## Port provenance {#provenance}

The distinction that matters for downgrade resistance is not the value
of the port but where the client obtained it.

An RPC client may learn the port for a program from the server's
RPCBIND service {{RFC1833}}.  RPCBIND replies are not authenticated.
An attacker who substitutes a port in an RPCBIND reply thereby
substitutes the first label of the TLSA owner name the client will
query.  The query is then made at a name for which the operator
published nothing, the validating resolver returns an authenticated
denial of existence, and the client assigns the outcome class
SECURE_ABSENT ({{outcomes}}).  No floor is pinned, and a client in
opportunistic mode proceeds as though the operator had published
nothing at all.

Accordingly:

* DANE authentication as specified in {{authn}} applies at whatever
  port the client connects to, whatever the provenance of that port.

* A client MUST NOT pin a security floor ({{floor}}) on the basis of a
  DNS outcome derived from a port the client obtained from an
  unauthenticated source.  Ports obtained from local configuration,
  including a configured default for the RPC program, are trusted for
  this purpose; ports obtained from an unauthenticated RPCBIND reply,
  or from any other unauthenticated in-band source, are not.

A TLSA RRset can authenticate a server at a port the client already
knew.  It cannot retroactively secure the client's selection of that
port.  {{sec-ports}} describes how a client obtains ports from an
authenticated source.

## Publishing and key rollover {#rollover}

Publishers MUST observe the requirements of Section 8 of {{RFC7671}},
in particular during key rollover: for each combination of certificate
usage, selector, and matching type it publishes, the RRset must at all
times contain a record matching the certificate that every server
answering for the name may present.  A client that has pinned a floor
on the strength of an RRset will fail rather than fall back when the
RRset and the certificate disagree, so a rollover performed in the
wrong order takes the service down instead of silently reducing its
security.  That is the intended behavior, but operators should plan
for it.

# The Reference Name {#refname}

## Requirements on the reference name

The TLSA base domains a client considers MUST be derived from the
reference name by which the client selected the server, as specified
in {{lookup}}.

A client MUST NOT use a name obtained by reverse resolution of the
server's network address as a reference name, or as the basis for one.
Reverse resolution answers a question the client did not ask: it
reports a name that the operator of the address block chose to
associate with the address, which is not evidence that the client
intended to reach the service named by it.  Accepting such a name
would permit an entity that controls a reverse zone to select the TLSA
RRset against which the client authenticates.

Before treating a configured value as a reference name, a client MUST
apply the following input contract.

* If the value is an IPv4 or IPv6 address literal, including an IPv6
  literal bearing a zone identifier, it is not a DNS name.  The
  destination carries no DANE binding; see {{no-dane}}.

* An internationalized domain name MUST be converted to A-label form
  {{RFC5890}} before it is used to construct an owner name, as
  Section 3 of {{RFC6698}} requires.

* The value MUST satisfy the syntax and length limits for DNS names in
  {{RFC1035}}, in both wire and presentation form.  A value with an
  empty or over-long label, or one that exceeds the total name length
  limit once the port and transport labels have been prepended, is not
  usable as a reference name, and the association attempt is handled
  as in {{no-dane}}.

* ASCII case is not significant.  A client that compares reference
  names -- to decide whether two association attempts concern the same
  server association, for instance -- MUST compare them
  case-insensitively.

* A trailing empty label, written as a trailing dot in presentation
  form, is retained when constructing DNS queries and removed when the
  name is used as a Server Name Indication (SNI) value {{RFC6066}} or
  as a
  PKIX reference identifier.

## Destinations that carry no DANE binding {#no-dane}

A destination selected by IP address literal has no DNS name from
which a TLSA base domain could be derived, and DANE does not apply to
it; this matches the treatment of address literals in Section 2.2 of
{{RFC7672}}.  The same holds for a destination whose configured name
fails the input contract above.

For such a destination:

* In opportunistic mode, the client proceeds under {{RFC9289}}
  unchanged.  In particular, if the client authenticates the server at
  all, it does so by the rules of Section 5.2.1 of {{RFC9289}}, which
  provide for matching an iPAddress subjectAltName.

* In mandatory mode, the association attempt fails ({{modes}}).

# Locating the TLSA RRset {#lookup}

## Resolver trust {#resolver}

Every guarantee in this document rests on the client obtaining DNSSEC
validation states it can trust.  A client that accepts the AD bit from
a remote validating resolver has moved its trust to that resolver and
to the path between them, which is precisely the kind of unprotected
path this document exists to defend against.

Accordingly, a client implementing this document SHOULD validate
DNSSEC responses itself, or obtain them from a validating resolver it
trusts over a channel whose integrity is protected.

A client whose trust anchors are missing cannot distinguish an
unsigned zone from a signed one, and the failure mode of guessing
wrongly is silent loss of protection.  {{outcomes}} therefore classes
a failure to load, read, or parse those trust anchors as ERROR, and
not as INSECURE.  Where the trust anchor is maintained automatically
{{RFC5011}}, an anchor that has fallen out of date is subject to the
same rule.

## DNS outcome classes {#outcomes}

A client reduces the result of its TLSA lookups for one reference
name, port, and transport to exactly one of the following five outcome
classes.  Throughout, "usable" has the meaning given in {{usable}}.

SECURE_USABLE:
: A DNSSEC-validated TLSA RRset was found, and at least one record in
  it is usable.  The client authenticates the server by DANE.

SECURE_UNUSABLE:
: A DNSSEC-validated TLSA RRset was found, and no record in
  it is usable.  The operator has committed to TLS, but the client
  cannot perform DANE authentication against what was published.

SECURE_ABSENT:
: The candidate base domains were exhausted without finding a
  validated TLSA RRset, and the last candidate evaluated yielded a
  DNSSEC-validated denial of existence.  The operator has published no
  signed TLSA RRset for this service.

INSECURE:
: The search ended at a TLSA owner name that lies in a provably
  unsigned span of the DNS.  DANE does not apply, and no conclusion
  can be drawn from the absence or presence of records.

ERROR:
: The client could not obtain a validated answer.  This class covers a
  "bogus" or "indeterminate" validation result, a timeout, a SERVFAIL
  or other error response, a malformed reply, a failure to load, read,
  or parse the resolver's trust anchors, and any other condition that
  prevents the client from assigning one of the four classes above.

An ERROR outcome MUST NOT be treated as equivalent to INSECURE, and
MUST NOT authorize cleartext operation.  The reasoning is that of
Sections 2.1.1 and 2.1.2 of {{RFC7672}}: the conditions that produce
ERROR are exactly the conditions an attacker can produce at will, so
a client that degrades gracefully on ERROR has no downgrade
resistance at all.
An implementation MAY retry a lookup that produced ERROR; if no
attempt yields a validated answer, the outcome remains ERROR.

## Candidate TLSA base domains {#candidates}

RPC-with-TLS has no service location indirection of the kind that MX
or SRV records provide, so the redirection case that Section 7 of
{{RFC7671}} addresses arises for RPC through CNAME aliasing.  A client
therefore determines an ordered list of candidate base domains before
querying for TLSA records, as shown in {{candidate-alg}}.

~~~
CandidateBaseDomains(name):

  Resolve the address records for "name" in each address family
  the client will use for this association attempt, following
  any CNAME chain hop by hop and noting the DNSSEC validation
  state of each link.

  If any step of that resolution is bogus or indeterminate, or
  fails to complete:
      return error

  If "name" is an alias, and in every address family resolved
  the chain reaches the same canonical name, and every link of
  every such chain is secure:
      return [ canonical-name, name ]

  return [ name ]
~~~
{: #candidate-alg title="Determining the candidate base domains"}

The single-element result is the conservative case, and covers every
situation in which the client cannot show that the redirection itself
was authenticated: an unaliased name, a chain with an insecure link, a
chain that resolves to different canonical names in different address
families, and a name for which no address records were sought.  A
client MUST NOT expand a chain that it has not validated end to end,
because an unvalidated CNAME lets whoever forged it choose the base
domain and therefore the TLSA RRset.

A CNAME encountered at a TLSA owner name itself is followed by
ordinary DNS resolution, subject to the same requirement that every
link be secure; a chain with an insecure or bogus link yields INSECURE
or ERROR respectively for that candidate.  Such a CNAME does not
change which candidate is the selected TLSA base domain, since it
redirects only the location of the records, not the identity of the
service.

## Evaluation and result reduction {#reduction}

A client evaluates the candidate list in order, as shown in
{{reduction-alg}}.

~~~
Evaluate(refname, port, proto):

  name = Normalize(refname)               ; input contract
  if name is an address literal:
      return "no DANE binding"

  candidates = CandidateBaseDomains(name) ; preceding figure
  if candidates is error:
      return ERROR

  for C in candidates:                    ; in order
      owner = "_" + port + "._" + proto + "." + C
      R = Lookup(owner, TLSA)

      if R is bogus or indeterminate or failed:
          return ERROR

      if R is secure and carries a TLSA RRset:
          selected_base_domain = C
          if AnyUsable(R):                ; usability filtering
              return SECURE_USABLE
          else:
              return SECURE_UNUSABLE

      if R is secure and is a denial of existence:
          continue

      if R is insecure:
          if C is not the last candidate:
              continue
          else:
              return INSECURE

  return SECURE_ABSENT
~~~
{: #reduction-alg title="TLSA lookup and result reduction"}

The rules this encodes, stated in prose:

* A validated TLSA RRset is final, whether or not the client can use
  the records in it.  Finding one stops the search; the client does
  not fall back to a later candidate in the hope of finding records it
  likes better.  This is what makes SECURE_UNUSABLE a distinct outcome
  rather than a variety of absence.

* A validated denial of existence continues the search, per Section 7
  of {{RFC7671}}, which directs a client that finds no TLSA record at
  the expanded name to query at the original name.  If no candidate
  remains, the outcome is SECURE_ABSENT.  An insecure answer likewise
  continues the search, since the operator may have published a
  signed RRset at a later candidate.

A client MUST assign the same outcome class as this procedure would
for the same DNS data.  Implementations are not required to perform
the queries in this order, or to perform queries whose result cannot
affect the outcome.

## Usable records and digest algorithm agility {#usable}

Whether a record is usable is determined before any attempt is made to
match it against a certificate, and a record that is usable but does
not match the server's certificate is an authentication failure, never
a reason to reclassify the RRset as unusable.  Conflating the two
would let an attacker who can influence the certificate a server
presents convert a DANE mismatch into a fallback.

A client determines the usable records in a validated TLSA RRset as
follows.

1. Discard any record whose RDATA is truncated, whose certificate
   association data has a length inconsistent with its matching type,
   or that is otherwise malformed.

2. Discard any record whose certificate usage, selector, or matching
   type the client has not implemented or has been configured not to
   use.  Certificate usage support is specified in {{usages}}.

3. Apply digest algorithm agility per Section 9 of {{RFC7671}}: for
   each combination of certificate usage and selector remaining, the
   client retains records with a matching type of Full(0), and records
   whose matching type is the strongest the client supports among
   those present for that usage and selector.  Records using a weaker
   supported matching type are discarded.

A matching type the client does not support MUST NOT suppress the
strongest type it does support, and malformed records MUST be
discarded in step 1 so that they do not influence the strength
selection in step 3.

If any record survives step 3, the RRset is usable and the outcome is
SECURE_USABLE.  If none does, the RRset is unusable and the outcome is
SECURE_UNUSABLE.

## The selected TLSA base domain, SNI, and reference identifiers {#selected}

The selected TLSA base domain is the candidate at which the evaluation
in {{reduction}} found a validated TLSA RRset.  It is defined only for
the outcome classes SECURE_USABLE and SECURE_UNUSABLE.

When the outcome is SECURE_USABLE, the selected TLSA base domain MUST
be sent as the Server Name Indication {{RFC6066}} value and, for
certificate usages other than DANE-EE(3), MUST be the primary
reference identifier for certificate name checks.  This is the rule of
Section 7 of {{RFC7671}}.

When the outcome is SECURE_UNUSABLE, the client MUST instead send the
original reference name as the Server Name Indication value, and MUST
use the original reference name as the reference identifier for the
PKIX name checks that {{behavior}} then requires.

This departs from Section 7 of {{RFC7671}}, and the reason is specific
to what SECURE_UNUSABLE means.  A DANE client is told to put the
expanded base domain in SNI because it is prepared to accept a
certificate issued for that name: the TLSA RRset at that name is the
authority it will authenticate against.  A client that can use no
record in the RRset is not prepared to accept such a certificate.  It
is about to fall back to PKIX authentication against the name the
administrator configured.  Sending the base domain in SNI would ask
the server for a certificate the client is then obliged to reject, and
a server that selects its certificate by SNI will supply exactly that
certificate.  The handshake then fails for a reason that has nothing
to do with the security of either name.

Note that an RRset of usage-2 records is SECURE_USABLE for a client
implementing this document, since {{usages}} requires DANE-TA(2)
support: DANE authenticates the peer, and the selected base domain is
a reference identifier again by the ordinary rule above.

The selected TLSA base domain is reported in the audit record
({{audit}}) in both cases, so that an operator can see which name the
policy decision was derived from.

# Authenticating the Server {#authn}

## Certificate usages {#usages}

A client implementing this document MUST support certificate usages
DANE-EE(3) and DANE-TA(2).  Both are used with the semantics given in
Sections 5.1 and 5.2 of {{RFC7671}} respectively.  Section 4 of
{{RFC7671}} recommends exactly this pair, and cautions that
simultaneous support for all four usages is not recommended.

Support for certificate usages PKIX-TA(0) and PKIX-EE(1) is OPTIONAL.
A client that does not support them treats records carrying them as
unusable in step 2 of {{usable}}.  Where such records are the only
ones published, the outcome is SECURE_UNUSABLE, and {{behavior}}
requires the client to authenticate the server by the PKIX rules of
Section 5.2.1 of {{RFC9289}}.  That is a weaker check than the
published records call for, since the client omits the additional
constraint the record expresses.  It is never weaker than
{{RFC9289}} alone, so the degradation is safe.

A client MUST support the selectors Cert(0) and SPKI(1) and the
matching types Full(0) and SHA2-256(1), which is the support that
Section 6 of {{RFC6698}} lets publishers rely on.  Support for
SHA2-512(2) is RECOMMENDED.

## DANE-EE(3) {#dane-ee}

Authentication by a DANE-EE(3) record consists of matching the
server's end-entity certificate, or its SubjectPublicKeyInfo, against
the certificate association data of a usable record, per Section 5.1
of {{RFC7671}}.

When such a match succeeds, the server is authenticated.  In
particular, and following Section 5.1 of {{RFC7671}}:

* The client MUST NOT reject the server because no name in the
  presented certificate matches the reference name or the selected
  TLSA base domain.  The binding of key to name is made by the TLSA
  record, not by the certificate.

* The client MUST NOT reject the server because the presented
  certificate is expired or not yet valid.  The validity of the
  binding is the validity of the DNSSEC signatures over the TLSA
  RRset.

* The client MUST NOT require that the presented certificate chain to
  a trusted certification authority.

Consequently a self-signed server certificate, published as a
DANE-EE(3) record with selector SPKI(1) and matching type
SHA2-256(1), is a fully conforming deployment; see
{{ta-distribution}}.

## DANE-TA(2) {#dane-ta}

Authentication by a DANE-TA(2) record consists of validating the
server's certificate chain to the trust anchor the record identifies,
per Section 5.2 of {{RFC7671}}, and then performing name checks
against the reference identifiers determined in {{selected}}.

Those name checks are performed per {{RFC9525}}, retaining the
restriction in Section 5.2.1 of {{RFC9289}} that a DNS domain name in
an RPC-with-TLS certificate MUST NOT contain the wildcard character
"*".

## Required client behavior by outcome class {#behavior}

{{behavior-table}} states what a client MUST do for each DNS outcome
class in each of the two active policy modes.  In every case where
authentication is required, failure of that authentication fails the
association attempt; see {{no-retry}}.

The requirement that TLS be used is carried by the security floor.
Where the DNS outcome was derived from a port of untrusted provenance,
{{provenance}} withholds that floor, and {{fallback}} then governs
whether the attempt may proceed in cleartext.  The authentication
requirements in the table apply to any (D)TLS session that is
established, whatever the provenance of the port.

| DNS outcome | Opportunistic mode | Mandatory mode |
|---|---|---|
| SECURE_USABLE | TLS is required, and the server MUST be authenticated by DANE per {{authn}}. PKIX authentication MUST NOT be substituted for it. | As for opportunistic. |
| SECURE_UNUSABLE | TLS is required, and the server MUST be authenticated per Section 5.2.1 of {{RFC9289}}. | The attempt MUST fail. |
| SECURE_ABSENT | No additional requirement; {{RFC9289}} applies unchanged. | The attempt MUST fail. |
| INSECURE | No additional requirement; {{RFC9289}} applies unchanged. | The attempt MUST fail. |
| ERROR | The attempt MUST fail. | The attempt MUST fail. |
{: #behavior-table title="Required client behavior by DNS outcome class"}

The SECURE_USABLE row is the central requirement of this document.
Where the client has a validated, usable TLSA RRset, DANE governs.  A
client MUST NOT accept a PKIX authentication in place of the DANE
authentication that the RRset calls for, however well-formed the
certificate chain and however trusted the certification authority that
issued it.  Permitting that substitution would return control of the
association's authentication to whoever can obtain a certificate for
the name, which is the outcome the TLSA RRset was published to
prevent.

The SECURE_UNUSABLE row strengthens the corresponding guidance in
Section 10.3 of {{RFC7671}} and Section 2.2 of {{RFC7672}}, both of
which require only unauthenticated TLS in this case.  Section 10.3 of
{{RFC7671}} anticipates such a strengthening, and conditions it on
whether expecting the stronger behavior is realistic for the
application protocol in question.  For RPC-with-TLS it is, and the
intermediate position those documents take is not available in any
case.  Section 4.2 of {{RFC9289}} gives two modes of client
deployment, server-only host authentication and mutual host
authentication, and the client authenticates the server in both.  An
RPC-with-TLS client may be anonymous to the server; the server is
never anonymous to the client.  Section 5.2 of {{RFC9289}} offers only
two peer authentication mechanisms to that end, PKIX trust and
pre-shared keys.  Accepting unauthenticated TLS
here would be a downgrade relative to the base specification rather
than an improvement on cleartext.

\[\[TODO: Whether this row should instead require only the
unauthenticated TLS that Section 10.3 of {{RFC7671}} calls for, or
fail the attempt as mandatory mode does, is open.
https://github.com/chucklever/i-d-rpc-tls-dane/issues/1 \]\]

# Downgrade Resistance {#downgrade}

## The security floor {#floor}

A DNS outcome class of SECURE_USABLE or SECURE_UNUSABLE pins a
security floor for the server association, except where
{{provenance}} withholds it: the client MUST NOT operate that
association at a security level weaker than an authenticated TLS
session, and MUST fail the association attempt rather than do so.

The floor is a property of the server association, not of the
connection on which it was determined.  Once pinned, it applies to
every subsequent association attempt for that association, and to
every transport that joins it; see {{assoc-scope}}.

The floor is stated in terms of the security level reached rather than
in terms of any particular attack.  Two instances of it are visible
today.  The first is the STRIPTLS attack of Section 6.1.1 of
{{RFC9289}}, in which an attacker suppresses or rewrites the cleartext
AUTH_TLS exchange so that the client believes TLS is unavailable;
{{probe}} specifies the client's response.  The second is any
mechanism by which an attacker induces a client to select a transport
or path for which the client would apply weaker protection.  A
document that specifies RPC over an additional transport can cite this
section for the second case without restating it.

## AUTH_TLS probe outcomes {#probe}

Section 4.1 of {{RFC9289}} specifies that a client that does not
receive the "STARTTLS" indication MUST NOT send a ClientHello, and
that "RPC operation may continue, depending on local policy, but
without confidentiality, integrity, or peer authentication protection
from (D)TLS".  This document specifies that local policy for a client
implementing DANE.

A client classifies the result of the AUTH_TLS probe into exactly one
of the following outcomes.

ACCEPTED:
: A Reply was received with a reply_stat of MSG_ACCEPTED and an
  AUTH_NONE verifier containing the "STARTTLS" token, as specified in
  Section 4.1 of {{RFC9289}}.

DECLINED:
: A complete, well-formed Reply to the probe was received that
  indicates the server does not support RPC-with-TLS.  This comprises
  a reply_stat of MSG_ACCEPTED with an AUTH_NONE verifier that does
  not carry the "STARTTLS" token, and a reply_stat of MSG_DENIED with
  a reject_stat of AUTH_ERROR.  These are the responses produced by a
  server that does not implement the AUTH_TLS authentication flavor.

RPCERR:
: A complete, well-formed Reply was received that is neither of the
  above -- for example a reply_stat of MSG_DENIED with a reject_stat
  of RPC_MISMATCH, or a reply_stat of MSG_ACCEPTED with a verifier
  whose flavor is not AUTH_NONE.

MALFORMED:
: A response was received that cannot be parsed as a well-formed RPC
  Reply to the probe, or whose verifier length is inconsistent with
  its declared flavor.

UNREACHABLE:
: The connection was refused or reset, or was closed before a Reply
  was received.

TIMEOUT:
: No response was received within the client's timeout.

LOCAL:
: A local resource failure prevented the probe from being sent, or its
  result from being determined.

## Cleartext fallback {#fallback}

{{fallback-table}} states whether the client may continue in
cleartext.

| Probe outcome | Floor pinned | No floor pinned |
|---|---|---|
| ACCEPTED | Proceed to the TLS handshake. | Proceed to the TLS handshake. |
| DECLINED | The attempt MUST fail. | Cleartext operation is permitted, subject to local policy, per Section 4.1 of {{RFC9289}}. |
| RPCERR | The attempt MUST fail. | The attempt MUST fail. |
| MALFORMED | The attempt MUST fail. | The attempt MUST fail. |
| UNREACHABLE | The attempt MUST fail. | The attempt MUST fail. |
| TIMEOUT | The attempt MUST fail. | The attempt MUST fail. |
| LOCAL | The attempt MUST fail. | The attempt MUST fail. |
{: #fallback-table title="Cleartext fallback by AUTH_TLS probe outcome"}

Only DECLINED permits cleartext operation, and only where no floor has
been pinned.  The other non-ACCEPTED outcomes are not evidence that
the server lacks RPC-with-TLS support; they are equally consistent
with an attacker interfering with the cleartext exchange, and they are
what such interference looks like.  A client that treats them as
declines has no downgrade resistance even against an attacker who
cannot forge a well-formed Reply.

\[\[TODO: Whether opportunistic mode should instead take the stricter
policy of Section 6.1.1 and Section 6.4 of {{RFC9289}}, at the cost of
reachability to servers that predate it, is open.
https://github.com/chucklever/i-d-rpc-tls-dane/issues/4 \]\]

Note that the DECLINED classification deliberately includes MSG_DENIED
with AUTH_ERROR, because that is how a server predating {{RFC9289}}
rejects an unrecognized authentication flavor.  Classifying it
otherwise would break the interoperability that the AUTH_TLS probe
exists to provide.

## Failure after a handshake is attempted {#no-retry}

Once the AUTH_TLS probe has been ACCEPTED and a (D)TLS handshake has
been attempted, the client MUST NOT retry the association attempt in
cleartext, whatever the DNS outcome class and whatever the reason the
handshake or the subsequent authentication failed.  This holds for
DANE mismatches, PKIX validation failures where PKIX applies, TLS
negotiation failures, and the unavailability of whatever local
component performs the handshake.

Section 4.1 of {{RFC9289}} describes a client that reports a
handshake failure after a successful probe to the upper layer the
same way it reports an AUTH_ERROR rejection from the server.  For a
client implementing this document, that behavior is a requirement
rather than a description.

## Coherence within an association attempt {#coherence}

This document does not specify how an implementation obtains DNS data,
how many times within one association attempt it evaluates the
procedure in {{lookup}}, or how a policy result determined at one
point in the attempt reaches the point at which the handshake is
authenticated.  Those are implementation matters.  Two properties are
required of any such arrangement.

* A client MUST evaluate DANE policy from DNS data that is current at
  the time of the association attempt.  It MUST NOT reuse a result
  obtained for an earlier attempt beyond the validity of the DNS data
  the result was derived from.

* Within one association attempt, a client MUST NOT conclude at a
  security level weaker than any determination it has already made
  during that attempt.  Where two evaluations during one attempt
  disagree, the stronger conclusion governs.

The second property is what makes the mechanism resistant to an
attacker who can affect the timing of DNS answers.  Concretely: if a
client determines SECURE_USABLE early in an attempt and a later
evaluation within the same attempt yields SECURE_UNUSABLE,
SECURE_ABSENT, INSECURE, or ERROR, the attempt MUST fail rather than
proceed under the weaker conclusion.  A client MAY act on a
strengthened conclusion -- a later evaluation that finds a usable
RRset where an earlier one did not -- since doing so cannot lower the
security of the attempt.

Legitimate causes of disagreement exist, such as a TLSA RRset
republished during a key rollover, and a client that fails such an
attempt will succeed on a subsequent one evaluated wholly against the
new data.  Failing and retrying is the correct handling: the client
cannot distinguish a rollover from an attack from within a single
attempt.

# Association Scope and Policy Granularity {#assoc-scope}

## Policy is per association

The DANE policy mode, the reference name, and any pinned security
floor are properties of a server association.  A client MUST be able
to apply different policies concurrently to different server
associations, since a single host commonly contacts servers whose
operators differ in whether they have deployed DNSSEC and published
TLSA records.

A client that shares underlying state between server associations --
connection caching, session reuse, or an internal client object shared
between two mounts of the same server -- MUST NOT share it between
associations whose DANE policy modes differ, or whose reference names
differ.  Two names that resolve to the same address may have different
TLSA RRsets published for them, and an association established under
one name has not authenticated the server for the other.

## Transports joining an association later {#add-xprt}

A client may add transports to an existing server association after it
is established, for additional bandwidth or to make use of additional
server network paths.

While a security floor is pinned for an association, a transport MUST
NOT join that association unless it carries the association's
reference name and its own evaluation meets the association's floor.
A transport whose destination was learned as an address literal
therefore cannot join a floor-pinned association, since no DANE
evaluation is possible for it ({{no-dane}}).  A client MUST refuse
such an addition and record the refusal ({{audit}}); the association
continues over the transports that do meet its floor.

## Derived associations {#derived}

Upper-layer protocols direct clients to establish further associations
whose destinations the client did not select by name.  NFSv4
{{RFC8881}} does this in at least three ways: a parallel NFS layout
identifies data servers, the file system location attributes identify
referral targets, and a migration event identifies a new location for
a file system.  Where the destination so identified is an address literal, or
a name the client cannot relate to the reference name of the
association it was directed from, the derived association has no DANE
binding of its own.

A security floor pinned for one server association does not extend to
a derived association.  A client MUST evaluate DANE policy
independently for each association it establishes, using the reference
name for that association if it has one.  In mandatory mode, a derived
association for which no DANE binding can be established fails
({{modes}}), even though this may render some upper-layer features
unusable ({{sec-derived}}).

Defining DNS-based identities for the destinations that upper-layer
protocols hand out -- so that a data server or a referral target can
be named rather than addressed -- is work for the specifications of
those protocols, and is outside the scope of this document.

# Auditing {#audit}

Section 6.1 of {{RFC9289}} requires implementations to provide an
audit log of RPC-with-TLS security mode selection.  A client
implementing this document MUST extend that log to cover the DANE
policy decision.  For each association attempt in which DANE policy
applied, the combined record MUST include:

* the reference name, and an indication of whether it was supplied by
  local configuration or derived some other way;

* the destination network address, port, and transport;

* the DANE policy mode in effect and where it came from;

* the DNS outcome class, and enough diagnostic detail to distinguish
  the conditions grouped under ERROR;

* the selected TLSA base domain, where one was determined;

* the AUTH_TLS probe outcome ({{probe}});

* the means by which the server was authenticated, if it was:
  DANE-EE(3), DANE-TA(2), or PKIX;

* for a DANE authentication, the usage, selector, and matching type
  of the record that matched; and

* the resulting disposition of the attempt: authenticated TLS,
  cleartext operation, or failure, with the reason for a failure.

The record MAY consist of correlatable events emitted by more than one
component, provided that the events can be joined and that together
they cover the whole list.  Implementations that divide the work of
{{overview}} between components will naturally produce such a split,
since no single component observes both the probe outcome and the
certificate that was matched.  A correlation identifier used to join
such events MUST NOT carry information that is not already disclosed
by the events themselves.

# Implementation Status {#impl-status}

This section is to be removed before publishing as an RFC.

This section records the status of known implementations of the
protocol defined by this specification at the time of posting of this
Internet-Draft, and is based on a proposal described in {{RFC7942}}.
The description of implementations in this section is intended to
assist the IETF in its decision processes in progressing drafts to
RFCs.  Please note that the listing of any individual implementation
here does not imply endorsement by the IETF.  Furthermore, no effort
has been spent to verify the information presented here that was
supplied by IETF contributors.  This is not intended as, and must not
be construed to be, a catalog of available implementations or their
features.  Readers are advised to note that other implementations may
exist.

## tlshd (ktls-utils)

Organization:
: The ktls-utils project.

Description:
: tlshd is the userspace handshake agent used by the Linux kernel's
  TLS handshake service.  It performs the (D)TLS handshake on behalf
  of in-kernel RPC-with-TLS consumers.

Implementation:
: https://github.com/oracle/ktls-utils

Level of maturity:
: Prototype.  The DANE support is not part of a released version at
  the time of writing, and is disabled by default.

Coverage:
: The reference-name input contract ({{refname}}); the candidate
  determination and result reduction of {{lookup}}, including secure
  CNAME expansion; the five outcome classes of {{outcomes}}; the
  usability filtering and digest algorithm agility of {{usable}}; the
  reference-identity rules of {{selected}}; certificate usage
  DANE-EE(3) ({{dane-ee}}); and the authentication behavior of
  {{behavior}} for both the client-anonymous and the mutually
  authenticated handshake path.

: Not implemented: certificate usage DANE-TA(2), DTLS over UDP, and
  the association-scope enforcement of {{assoc-scope}}, which belongs to the
  RPC client rather than to the handshake agent.

Licensing:
: GPLv2.

Contact:
: The editor of this document.

Experience:
: The implementation was exercised against publicly available DANE
  test zones as well as against a locally signed test zone.  Two
  findings are reflected in the text of this document.

: First, the reference-identity rule in {{selected}} for the
  SECURE_UNUSABLE class was added as a result of implementation.  A
  securely CNAME-expanded name whose TLSA RRset contained no record
  the implementation could use caused the client to send the expanded
  base domain in SNI, per Section 7 of {{RFC7671}}, and then to
  perform PKIX name checks against the original reference name.  The
  server selected a certificate on the basis of SNI, and the handshake
  failed.  {{selected}} states the resulting rule and its rationale.

: Second, the implementation performs the usability filtering of
  {{usable}}, including digest algorithm agility, in its own code
  rather than relying on the TLS library's DANE support, so that the
  outcome classification does not depend on library internals.  The
  library's raw verification interface reports parse success in its
  return value and verification results in a separate output
  parameter; an implementation that checks only the return value
  accepts unauthenticated peers.  Implementers are cautioned to check
  both.


# Security Considerations {#security}

The security considerations of {{RFC9289}}, {{RFC6698}}, {{RFC7671}},
and {{RFC4033}} apply.

## What DANE authentication does and does not establish

A successful DANE-EE(3) match establishes that the peer holds the key
that the operator of the TLSA base domain's zone published for that
service at that port and transport.  It establishes nothing about the
names in the presented certificate, its validity dates, or its issuer
({{dane-ee}}).  A deployment that relies on certificate contents for
authorization -- an extended key usage check, a certificate policy, a
subjectAltName URI -- as Section 5.2.1 of {{RFC9289}} permits, must
continue to perform those checks independently; a DANE match does not
perform them.

Control of the zone that publishes the TLSA RRset is control of the
service's authentication.  This concentrates trust in the zone
operator and in the DNSSEC chain above it, and removes it from the
certification authorities the client would otherwise trust.  For the
deployments described in {{ta-distribution}} that is the point: the
party that operates the server also operates the zone.  Where that is
not so -- where DNS is operated by a third party -- the trust
concentration should be evaluated before deployment.

## Replay and the limits of revocation {#replay}

DNSSEC provides no way to revoke a signed RRset before its signatures
expire (Section 11 of {{RFC7671}}).  Two consequences follow, and both
are bounded by the signature validity period rather than by anything
the client can do.

An attacker who captured a signed denial of existence for a TLSA owner
name before the operator published the RRset can replay it within that
period.  The client assigns SECURE_ABSENT, pins no floor, and is left
where {{RFC9289}} alone would have left it.  This is the residual
described in {{adaptive}}.

An attacker who holds a key the operator has withdrawn can replay the
TLSA RRset that still names it, and a client that matches it will
authenticate the peer.  {{dane-ee}} directs a client to disregard the
presented certificate's validity dates, so the RRset's signatures are
the only expiry that applies.  A client cannot distinguish a replayed
RRset from a current one, so the mitigation is operational and belongs
to the publisher; see {{ta-distribution}}.

This document does not require a client to re-evaluate DANE policy for
an association that is already established.  {{coherence}} bounds the
reuse of a result across association attempts, and a client that
establishes a new transport for an association evaluates afresh
({{add-xprt}}), but a long-lived session established against an RRset
that has since been withdrawn continues under the conclusion reached
when it was established.

## Fail-closed behavior is a denial-of-service surface

The rules in {{behavior}}, {{fallback}}, and {{coherence}} require a
client to fail an association attempt in circumstances where an
{{RFC9289}} client would have continued.  An attacker who can disrupt
the client's DNS -- by dropping responses, by inducing SERVFAIL, or by
corrupting signatures to produce a bogus validation result -- can
therefore prevent the client from establishing associations.

This is a deliberate trade.  The alternative, degrading to cleartext
or to unauthenticated TLS when DNS is disrupted, hands the same
attacker the ability to strip protection silently, which is the attack
this document exists to prevent.  An attacker who can disrupt DNS can
in any case usually disrupt the RPC traffic itself.  Operators for
whom availability outweighs confidentiality can express that by
configuring opportunistic rather than mandatory mode, and by leaving
DANE disabled for associations where even the opportunistic floor is
unacceptable.

## Unauthenticated port selection {#sec-ports}

The rule in {{provenance}}, that a floor is pinned only on a port of
trusted provenance, keeps an attacker who substitutes the port in an
RPCBIND {{RFC1833}} reply from pinning a floor the operator did not
intend.  It does not prevent the SECURE_ABSENT outcome that the
substitution produces, so a client that obtains its ports from RPCBIND
is left as exposed to cleartext fallback as an {{RFC9289}} client.

An RPCBIND reply carries a universal address, not only a port:
RPCBPROC_GETADDR "returns the universal address on which the program
is awaiting call requests" (Section 2.2.1 of {{RFC1833}}).  An
attacker who can rewrite that reply can therefore redirect the client
to a different host as readily as to a different port.  Where DANE
applies, that redirection is defended without further machinery, since
the substituted host cannot present a certificate matching the TLSA
RRset published for the reference name, and the handshake fails.
Where the port was substituted as well, the outcome is SECURE_ABSENT,
no floor is pinned, and neither the address nor the port is protected.
The two cases differ only in whether the client reaches a TLS
handshake at all.

The remedy available today is to protect RPCBIND itself.  RPCBIND is
an RPC program, and Section 4.1 of {{RFC9289}} requires an RPC server
to listen for TLS-protected programs on the same ports it uses without
TLS.  A client can therefore send an AUTH_TLS probe to the RPCBIND
port, authenticate the RPCBIND service by the procedures in this
document against the TLSA RRset published at the owner name that port
and transport yield, and make its lookups over the resulting session.
The ports it learns then come from an authenticated source.  This
requires no new protocol, and it raises no bootstrap problem, because
the RPCBIND port is well known and is therefore of trusted provenance
under {{provenance}}.

A session established to the RPCBIND port authenticates the RPCBIND
service alone.  The service the client goes on to contact is
authenticated separately, against the TLSA RRset for its own port,
and a security floor determined for one is not a floor for the
other.  An operator who protects RPCBIND but publishes no TLSA RRset
for the service has secured the discovery step alone; one who
publishes for the service but leaves RPCBIND unprotected has left the
guarantees in this document resting on an unauthenticated reply.

## Derived associations {#sec-derived}

A security floor does not extend to an association whose destination
an upper-layer protocol supplied ({{derived}}).  The practical
consequence for NFSv4 {{RFC8881}} is that data-path
traffic is protected only as well as the weakest derived association
carrying it.  A client that has pinned a floor for its metadata
association, and then reads and writes file data over parallel NFS
data server connections established from address literals, has
obtained no DANE protection for the data itself.  Operators should not
infer from a floor pinned on the metadata association that the data
path is equivalently protected.  A client in mandatory mode fails such
connections rather than establishing them ({{derived}}), which makes
the limitation visible rather than silent, at the cost of the feature.

## Privacy considerations

TLSA queries for RPC services disclose, to any observer of the
client's DNS traffic, which RPC services the client is about to
contact and on which ports, at the time it is about to contact them.
The names and addresses involved are already disclosed by the address
resolution the client must perform in any case, and by the RPC traffic
itself; the port and transport labels in the owner name are
additional.  This is the same exposure discussed in Section 6.1.2 of
{{RFC9289}} for the cleartext portion of association establishment,
and the same mitigations -- protecting the client's DNS transport, or
resolving locally -- apply.  Pervasive monitoring {{RFC7258}} of DNS
traffic is a known concern for DANE generally; {{RFC9076}} surveys
what DNS transactions disclose to observers.

## Client authentication {#client-auth}

This document specifies the authentication of a server to a client
only.  {{RFC9289}} also provides for mutual authentication, in which
the client presents a certificate that the server validates by PKIX
and identifies by the tuple of serial number and issuer.  DANE-based
authentication in that direction is not specified here.

The generic mechanism for it exists: {{I-D.ietf-dance-client-auth}}
defines a TLS extension by which a client conveys the owner name of
its own TLSA records, together with the semantics of those records;
that mechanism updates {{RFC6698}} and {{RFC7671}}.
An RPC profile of that mechanism would additionally need to choose the
owner-name form for RPC peers, restrict the certificate usages, and
specify how a DANE-authenticated client name maps onto RPC-layer
authorization -- the role that a machine credential plays for NFS
today.  That is a separate and short document, and is expected to
follow the mechanism it would profile.

Until then, a deployment that requires mutual authentication uses the
PKIX mechanism of Section 5.2.1 of {{RFC9289}} for the client
direction while using DANE, as specified here, for the server
direction.  The two are independent: {{behavior}} applies to the
server's certificate whether or not the client presents one of its
own.

# IANA Considerations {#iana}

This document requests no IANA actions.


--- back

# Deployment Considerations {#deployment}

## Publishing TLSA records for RPC services {#ta-distribution}

The simplest conforming deployment, and the one that addresses the
operational problem described in {{intro}}, is to publish for
each service a single DANE-EE(3) record with selector SPKI(1) and
matching type SHA2-256(1), written "3 1 1", in a DNSSEC-signed zone:

~~~
_2049._tcp.nfs.example.com. IN TLSA 3 1 1 (
                               2A1B4C...  )
~~~
{: title="A minimal TLSA RRset for an NFS service"}

Clients then need no certification authority material for the servers
in that zone, and the operator maintains the binding in one place.  By
{{dane-ee}}, the server certificate may be self-signed, and its
notAfter date does not affect the outcome.  What an operator must do
to keep the RRset and its certificates in step, in particular during
key rollover, is specified in {{rollover}}.

The signature validity period the operator chooses bounds the replay
window described in {{replay}}.  Section 11 of {{RFC7671}} suggests
a lifetime of a few days for domains publishing high-value keys.

## Unsigned zones prove nothing {#unsigned}

An operator who has not signed the zone containing the service name
cannot obtain any of the properties in this document.  A client
querying for TLSA records in an unsigned zone obtains the outcome
INSECURE, whatever it finds there, and proceeds under {{RFC9289}}
unchanged.  Publishing a TLSA RRset without signing the zone gives an
attacker something to remove rather than the client something to rely
on.

The same is true of a denial of existence obtained from an unsigned
zone.  It is the validation of the denial, not the denial itself, that
lets a client conclude the operator published nothing.

## Downgrade resistance of opportunistic DANE {#adaptive}

Opportunistic mode ({{modes}}) adapts to what each operator has
deployed, which is what makes it usable across a mixed server
population.  It is worth stating why this adaptivity is not itself a
downgrade path.

Against a client that validates DNSSEC, an attacker who wants to move
a server from SECURE_USABLE to a weaker class must either forge a
denial of existence in a signed zone, which fails NSEC or NSEC3
validation, or strip signatures, which yields ERROR and therefore
failure rather than fallback.  The remaining class, INSECURE, arises
only from a genuinely unsigned delegation, which the attacker cannot
manufacture without control of the parent zone's signing key.

One path remains, and it requires neither forgery nor signature
stripping: replay of a signed denial of existence captured before
the operator published the RRset, which validates until its
signatures expire and leaves the client at SECURE_ABSENT with no
floor pinned.  {{replay}} describes that window and its bound.

Apart from that window, the outcome classes an attacker can reach from
SECURE_USABLE are the ones that fail the attempt.  A deployment that
wants to close the window as well can adopt the policy in Section 6.4
of {{RFC9289}}, which requires TLS and rejects a connection when host
authentication fails, whatever the DNS outcome.

This is the same argument that supports opportunistic DANE for SMTP
{{RFC7672}}, and the same property that makes fleet-wide deployment
practical: a client can be configured for opportunistic DANE once and
will obtain the stronger behavior for every server whose operator has
published records, without per-server configuration and without
breaking against the servers whose operators have not.  On the
relationship between this adaptivity and opportunistic security in
general, see {{RFC7435}}.

# Open Issues {#open-issues}

This section is to be removed before publishing as an RFC.

Each item is tracked as an issue in this document's issue tracker,
where the detail and the discussion live.

* {{behavior}}: whether the SECURE_UNUSABLE class requires an
  authenticated TLS session, the unauthenticated TLS that Section 10.3
  of {{RFC7671}} calls for, or a failed attempt.
  [Issue 1](https://github.com/chucklever/i-d-rpc-tls-dane/issues/1)

* {{selected}}: whether SNI carries the original reference name or the
  selected TLSA base domain for the SECURE_UNUSABLE class.
  [Issue 2](https://github.com/chucklever/i-d-rpc-tls-dane/issues/2)

* {{probe}}: whether the partition of AUTH_TLS probe results, and in
  particular which of them count as DECLINED, preserves reachability
  to the pre-{{RFC9289}} server population.
  [Issue 3](https://github.com/chucklever/i-d-rpc-tls-dane/issues/3)

* {{fallback}}: whether cleartext operation remains permitted where no
  floor has been pinned and the server declines, or opportunistic mode
  takes the stricter policy of Section 6.1.1 of {{RFC9289}}.
  [Issue 4](https://github.com/chucklever/i-d-rpc-tls-dane/issues/4)

* {{usages}}: whether support for PKIX-TA(0) and PKIX-EE(1) stays
  optional, or this document specifies behavior for those usages.
  [Issue 5](https://github.com/chucklever/i-d-rpc-tls-dane/issues/5)

* {{sec-ports}}: whether obtaining service ports over an authenticated
  channel is required, recommended, or left as description.
  [Issue 6](https://github.com/chucklever/i-d-rpc-tls-dane/issues/6)

* {{scope}}: whether an owner-name convention is needed for transports
  other than those {{RFC9289}} defines.
  [Issue 7](https://github.com/chucklever/i-d-rpc-tls-dane/issues/7)

* {{scope}}: whether an association using the pre-shared key mechanism
  of Section 5.2.2 of {{RFC9289}} consults TLSA records for downgrade
  resistance.
  [Issue 8](https://github.com/chucklever/i-d-rpc-tls-dane/issues/8)

# Acknowledgments
{:numbered="false"}

The editor is grateful to
Bill Baker,
Greg Marsden,
and
Martin Thomson
for their input and support.

Special thanks to
Area Director
Gorry Fairhurst,
NFSv4 Working Group Chair
Brian Pawlowski,
and
NFSv4 Working Group Secretary
Thomas Haynes
for their guidance and oversight.
