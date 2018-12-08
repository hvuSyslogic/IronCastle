using org.bouncycastle.est;
using org.bouncycastle.asn1.nist;

using System;

namespace org.bouncycastle.est
{

	using DERNull = org.bouncycastle.asn1.DERNull;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DefaultDigestAlgorithmIdentifierFinder = org.bouncycastle.@operator.DefaultDigestAlgorithmIdentifierFinder;
	using DigestAlgorithmIdentifierFinder = org.bouncycastle.@operator.DigestAlgorithmIdentifierFinder;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;
	using Base64 = org.bouncycastle.util.encoders.Base64;
	using Hex = org.bouncycastle.util.encoders.Hex;

	/// <summary>
	/// Provides stock implementations for basic auth and digest auth.
	/// </summary>
	public class HttpAuth : ESTAuth
	{
		private static readonly DigestAlgorithmIdentifierFinder digestAlgorithmIdentifierFinder = new DefaultDigestAlgorithmIdentifierFinder();

		private readonly string realm;
		private readonly string username;
		private readonly char[] password;
		private readonly SecureRandom nonceGenerator;
		private readonly DigestCalculatorProvider digestCalculatorProvider;

		private static readonly Set<string> validParts;

		static HttpAuth()
		{
			HashSet<string> s = new HashSet<string>();
			s.add("realm");
			s.add("nonce");
			s.add("opaque");
			s.add("algorithm");
			s.add("qop");
			validParts = Collections.unmodifiableSet(s);
		}

		/// <summary>
		/// Base constructor for basic auth.
		/// </summary>
		/// <param name="username"> user id. </param>
		/// <param name="password"> user's password. </param>
		public HttpAuth(string username, char[] password) : this(null, username, password, null, null)
		{
		}

		/// <summary>
		/// Constructor for basic auth with a specified realm.
		/// </summary>
		/// <param name="realm">    expected server realm. </param>
		/// <param name="username"> user id. </param>
		/// <param name="password"> user's password. </param>
		public HttpAuth(string realm, string username, char[] password) : this(realm, username, password, null, null)
		{
		}

		/// <summary>
		/// Base constructor for digest auth. The realm will be set by
		/// </summary>
		/// <param name="username">                 user id. </param>
		/// <param name="password">                 user's password. </param>
		/// <param name="nonceGenerator">           random source for generating nonces. </param>
		/// <param name="digestCalculatorProvider"> provider for digest calculators needed for calculating hashes. </param>
		public HttpAuth(string username, char[] password, SecureRandom nonceGenerator, DigestCalculatorProvider digestCalculatorProvider) : this(null, username, password, nonceGenerator, digestCalculatorProvider)
		{
		}

		/// <summary>
		/// Constructor for digest auth with a specified realm.
		/// </summary>
		/// <param name="realm">                    expected server realm. </param>
		/// <param name="username">                 user id. </param>
		/// <param name="password">                 user's password. </param>
		/// <param name="nonceGenerator">           random source for generating nonces. </param>
		/// <param name="digestCalculatorProvider"> provider for digest calculators needed for calculating hashes. </param>
		public HttpAuth(string realm, string username, char[] password, SecureRandom nonceGenerator, DigestCalculatorProvider digestCalculatorProvider)
		{
			this.realm = realm;
			this.username = username;
			this.password = password;
			this.nonceGenerator = nonceGenerator;
			this.digestCalculatorProvider = digestCalculatorProvider;
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public void applyAuth(final ESTRequestBuilder reqBldr)
		public virtual void applyAuth(ESTRequestBuilder reqBldr)
		{
			reqBldr.withHijacker(new ESTHijackerAnonymousInnerClass(this, reqBldr));
		}

		public class ESTHijackerAnonymousInnerClass : ESTHijacker
		{
			private readonly HttpAuth outerInstance;

			private ESTRequestBuilder reqBldr;

			public ESTHijackerAnonymousInnerClass(HttpAuth outerInstance, ESTRequestBuilder reqBldr)
			{
				this.outerInstance = outerInstance;
				this.reqBldr = reqBldr;
			}

			public ESTResponse hijack(ESTRequest req, Source sock)
			{
				ESTResponse res = new ESTResponse(req, sock);

				if (res.getStatusCode() == 401)
				{
					string authHeader = res.getHeader("WWW-Authenticate");
					if (string.ReferenceEquals(authHeader, null))
					{
						throw new ESTException("Status of 401 but no WWW-Authenticate header");
					}

					authHeader = Strings.toLowerCase(authHeader);

					if (authHeader.StartsWith("digest", StringComparison.Ordinal))
					{
						res = outerInstance.doDigestFunction(res);
					}
					else if (authHeader.StartsWith("basic", StringComparison.Ordinal))
					{
						res.close(); // Close off the last reqBldr.

						//
						// Check realm field from header.
						//
						Map<string, string> s = HttpUtil.splitCSL("Basic", res.getHeader("WWW-Authenticate"));

						//
						// If no realm supplied it will not check the server realm. TODO elaborate in documentation.
						//
						if (!string.ReferenceEquals(outerInstance.realm, null))
						{
							if (!outerInstance.realm.Equals(s.get("realm")))
							{
								// Not equal then fail.
								throw new ESTException("Supplied realm '" + outerInstance.realm + "' does not match server realm '" + s.get("realm") + "'", null, 401, null);
							}
						}

						//
						// Prepare basic auth answer.
						//
						ESTRequestBuilder answer = (new ESTRequestBuilder(req)).withHijacker(null);

						if (!string.ReferenceEquals(outerInstance.realm, null) && outerInstance.realm.Length > 0)
						{
							answer.setHeader("WWW-Authenticate", @"Basic realm=""" + outerInstance.realm + @"""");
						}
						if (outerInstance.username.Contains(":"))
						{
							throw new IllegalArgumentException("User must not contain a ':'");
						}
						//userPass = username + ":" + password;
						char[] userPass = new char[outerInstance.username.Length + 1 + outerInstance.password.Length];
						JavaSystem.arraycopy(outerInstance.username.ToCharArray(), 0, userPass, 0, outerInstance.username.Length);
						userPass[outerInstance.username.Length] = ':';
						JavaSystem.arraycopy(outerInstance.password, 0, userPass, outerInstance.username.Length + 1, outerInstance.password.Length);

						answer.setHeader("Authorization", "Basic " + Base64.toBase64String(Strings.toByteArray(userPass)));

						res = req.getClient().doRequest(answer.build());

						Arrays.fill(userPass, (char)0);
					}
					else
					{
						throw new ESTException("Unknown auth mode: " + authHeader);
					}


					return res;
				}
				return res;
			}
		}

		private ESTResponse doDigestFunction(ESTResponse res)
		{
			res.close(); // Close off the last request.
			ESTRequest req = res.getOriginalRequest();


			Map<string, string> parts = null;
			try
			{
				parts = HttpUtil.splitCSL("Digest", res.getHeader("WWW-Authenticate"));
			}
			catch (Exception t)
			{
				throw new ESTException("Parsing WWW-Authentication header: " + t.Message, t, res.getStatusCode(), new ByteArrayInputStream(res.getHeader("WWW-Authenticate").GetBytes()));
			}


			string uri = null;
			try
			{
				uri = req.getURL().toURI().getPath();
			}
			catch (Exception e)
			{
				throw new IOException("unable to process URL in request: " + e.Message);
			}

			for (Iterator it = parts.keySet().iterator(); it.hasNext();)
			{
				object k = it.next();
				if (!validParts.contains(k))
				{
					throw new ESTException("Unrecognised entry in WWW-Authenticate header: '" + k + "'");
				}
			}

			string method = req.getMethod();
			string realm = parts.get("realm");
			string nonce = parts.get("nonce");
			string opaque = parts.get("opaque");
			string algorithm = parts.get("algorithm");
			string qop = parts.get("qop");


			List<string> qopMods = new ArrayList<string>(); // Preserve ordering.

			if (!string.ReferenceEquals(this.realm, null))
			{
				if (!this.realm.Equals(realm))
				{
					// Not equal then fail.
					throw new ESTException("Supplied realm '" + this.realm + "' does not match server realm '" + realm + "'", null, 401, null);
				}
			}

			// If an algorithm is not specified, default to MD5.
			if (string.ReferenceEquals(algorithm, null))
			{
				algorithm = "MD5";
			}

			if (algorithm.Length == 0)
			{
				throw new ESTException("WWW-Authenticate no algorithm defined.");
			}

			algorithm = Strings.toUpperCase(algorithm);

			if (!string.ReferenceEquals(qop, null))
			{
				if (qop.Length == 0)
				{
					throw new ESTException("QoP value is empty.");
				}

				qop = Strings.toLowerCase(qop);
				string[] s = qop.Split(",", true);
				for (int j = 0; j != s.Length; j++)
				{
					if (!s[j].Equals("auth") && !s[j].Equals("auth-int"))
					{
						throw new ESTException("QoP value unknown: '" + j + "'");
					}

					string jt = s[j].Trim();
					if (qopMods.contains(jt))
					{
						continue;
					}
					qopMods.add(jt);
				}
			}
			else
			{
				throw new ESTException("Qop is not defined in WWW-Authenticate header.");
			}


			AlgorithmIdentifier digestAlg = lookupDigest(algorithm);
			if (digestAlg == null || digestAlg.getAlgorithm() == null)
			{
				throw new IOException("auth digest algorithm unknown: " + algorithm);
			}

			DigestCalculator dCalc = getDigestCalculator(algorithm, digestAlg);
			OutputStream dOut = dCalc.getOutputStream();

			string crnonce = makeNonce(10); // TODO arbitrary?

			update(dOut, username);
			update(dOut, ":");
			update(dOut, realm);
			update(dOut, ":");
			update(dOut, password);

			dOut.close();

			byte[] ha1 = dCalc.getDigest();

			if (algorithm.EndsWith("-SESS", StringComparison.Ordinal))
			{
				DigestCalculator sessCalc = getDigestCalculator(algorithm, digestAlg);
				OutputStream sessOut = sessCalc.getOutputStream();

				string cs = Hex.toHexString(ha1);

				update(sessOut, cs);
				update(sessOut, ":");
				update(sessOut, nonce);
				update(sessOut, ":");
				update(sessOut, crnonce);

				sessOut.close();

				ha1 = sessCalc.getDigest();
			}

			string hashHa1 = Hex.toHexString(ha1);

			DigestCalculator authCalc = getDigestCalculator(algorithm, digestAlg);
			OutputStream authOut = authCalc.getOutputStream();

			if (qopMods.get(0).Equals("auth-int"))
			{
				DigestCalculator reqCalc = getDigestCalculator(algorithm, digestAlg);
				OutputStream reqOut = reqCalc.getOutputStream();

				req.writeData(reqOut);

				reqOut.close();

				byte[] b = reqCalc.getDigest();

				update(authOut, method);
				update(authOut, ":");
				update(authOut, uri);
				update(authOut, ":");
				update(authOut, Hex.toHexString(b));
			}
			else if (qopMods.get(0).Equals("auth"))
			{
				update(authOut, method);
				update(authOut, ":");
				update(authOut, uri);
			}

			authOut.close();

			string hashHa2 = Hex.toHexString(authCalc.getDigest());

			DigestCalculator responseCalc = getDigestCalculator(algorithm, digestAlg);
			OutputStream responseOut = responseCalc.getOutputStream();

			if (qopMods.contains("missing"))
			{
				update(responseOut, hashHa1);
				update(responseOut, ":");
				update(responseOut, nonce);
				update(responseOut, ":");
				update(responseOut, hashHa2);
			}
			else
			{
				update(responseOut, hashHa1);
				update(responseOut, ":");
				update(responseOut, nonce);
				update(responseOut, ":");
				update(responseOut, "00000001");
				update(responseOut, ":");
				update(responseOut, crnonce);
				update(responseOut, ":");

				if (qopMods.get(0).Equals("auth-int"))
				{
					update(responseOut, "auth-int");
				}
				else
				{
					update(responseOut, "auth");
				}

				update(responseOut, ":");
				update(responseOut, hashHa2);
			}

			responseOut.close();

			string digest = Hex.toHexString(responseCalc.getDigest());

			Map<string, string> hdr = new HashMap<string, string>();
			hdr.put("username", username);
			hdr.put("realm", realm);
			hdr.put("nonce", nonce);
			hdr.put("uri", uri);
			hdr.put("response", digest);
			if (qopMods.get(0).Equals("auth-int"))
			{
				hdr.put("qop", "auth-int");
				hdr.put("nc", "00000001");
				hdr.put("cnonce", crnonce);
			}
			else if (qopMods.get(0).Equals("auth"))
			{
				hdr.put("qop", "auth");
				hdr.put("nc", "00000001");
				hdr.put("cnonce", crnonce);
			}
			hdr.put("algorithm", algorithm);

			if (string.ReferenceEquals(opaque, null) || opaque.Length == 0)
			{
				hdr.put("opaque", makeNonce(20));
			}

			ESTRequestBuilder answer = (new ESTRequestBuilder(req)).withHijacker(null);

			answer.setHeader("Authorization", HttpUtil.mergeCSL("Digest", hdr));

			return req.getClient().doRequest(answer.build());
		}

		private DigestCalculator getDigestCalculator(string algorithm, AlgorithmIdentifier digestAlg)
		{
			DigestCalculator dCalc;
			try
			{
				dCalc = digestCalculatorProvider.get(digestAlg);
			}
			catch (OperatorCreationException e)
			{
				throw new IOException("cannot create digest calculator for " + algorithm + ": " + e.Message);
			}
			return dCalc;
		}

		private AlgorithmIdentifier lookupDigest(string algorithm)
		{
			if (algorithm.EndsWith("-SESS", StringComparison.Ordinal))
			{
				algorithm = algorithm.Substring(0, algorithm.Length - "-SESS".Length);
			}

			if (algorithm.Equals("SHA-512-256"))
			{
				return new AlgorithmIdentifier(NISTObjectIdentifiers_Fields.id_sha512_256, DERNull.INSTANCE);
			}

			return digestAlgorithmIdentifierFinder.find(algorithm);
		}

		private void update(OutputStream dOut, char[] value)
		{
			dOut.write(Strings.toUTF8ByteArray(value));
		}

		private void update(OutputStream dOut, string value)
		{
			dOut.write(Strings.toUTF8ByteArray(value));
		}

		private string makeNonce(int len)
		{
			byte[] b = new byte[len];
			nonceGenerator.nextBytes(b);
			return Hex.toHexString(b);
		}
	}

}