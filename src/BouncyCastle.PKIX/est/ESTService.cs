using org.bouncycastle.asn1.pkcs;

using System;

namespace org.bouncycastle.est
{

	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERPrintableString = org.bouncycastle.asn1.DERPrintableString;
	using ContentInfo = org.bouncycastle.asn1.cms.ContentInfo;
	using CsrAttrs = org.bouncycastle.asn1.est.CsrAttrs;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using X509CRLHolder = org.bouncycastle.cert.X509CRLHolder;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using CMCException = org.bouncycastle.cmc.CMCException;
	using SimplePKIResponse = org.bouncycastle.cmc.SimplePKIResponse;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;
	using PKCS10CertificationRequest = org.bouncycastle.pkcs.PKCS10CertificationRequest;
	using PKCS10CertificationRequestBuilder = org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
	using Selector = org.bouncycastle.util.Selector;
	using Store = org.bouncycastle.util.Store;
	using Base64 = org.bouncycastle.util.encoders.Base64;

	/// <summary>
	/// ESTService provides unified access to an EST server which is defined as implementing
	/// RFC7030.
	/// </summary>
	public class ESTService
	{
		protected internal const string CACERTS = "/cacerts";
		protected internal const string SIMPLE_ENROLL = "/simpleenroll";
		protected internal const string SIMPLE_REENROLL = "/simplereenroll";
		protected internal const string FULLCMC = "/fullcmc";
		protected internal const string SERVERGEN = "/serverkeygen";
		protected internal const string CSRATTRS = "/csrattrs";

		protected internal static readonly Set<string> illegalParts = new HashSet<string>();

		static ESTService()
		{
			illegalParts.add(CACERTS.Substring(1));
			illegalParts.add(SIMPLE_ENROLL.Substring(1));
			illegalParts.add(SIMPLE_REENROLL.Substring(1));
			illegalParts.add(FULLCMC.Substring(1));
			illegalParts.add(SERVERGEN.Substring(1));
			illegalParts.add(CSRATTRS.Substring(1));
		}


		private readonly string server;
		private readonly ESTClientProvider clientProvider;

		private static readonly Pattern pathInvalid = Pattern.compile(@"^[0-9a-zA-Z_\-.~!$&'()*+,;=]+");

		public ESTService(string serverAuthority, string label, ESTClientProvider clientProvider)
		{

			serverAuthority = verifyServer(serverAuthority);

			if (!string.ReferenceEquals(label, null))
			{
				label = verifyLabel(label);
				server = "https://" + serverAuthority + "/.well-known/est/" + label;
			}
			else
			{
				server = "https://" + serverAuthority + "/.well-known/est";
			}

			this.clientProvider = clientProvider;
		}

		/// <summary>
		/// Utility method to extract all the X509Certificates from a store and return them in an array.
		/// </summary>
		/// <param name="store"> The store. </param>
		/// <returns> An arrar of certificates/ </returns>
		public static X509CertificateHolder[] storeToArray(Store<X509CertificateHolder> store)
		{
			return storeToArray(store, null);
		}

		/// <summary>
		/// Utility method to extract all the X509Certificates from a store using a filter and to return them
		/// as an array.
		/// </summary>
		/// <param name="store">    The store. </param>
		/// <param name="selector"> The selector. </param>
		/// <returns> An array of X509Certificates. </returns>
		public static X509CertificateHolder[] storeToArray(Store<X509CertificateHolder> store, Selector<X509CertificateHolder> selector)
		{
			Collection<X509CertificateHolder> c = store.getMatches(selector);
			return c.toArray(new X509CertificateHolder[c.size()]);
		}

		/// <summary>
		/// Query the EST server for ca certificates.
		/// <para>
		/// RFC7030 leans heavily on the verification phases of TLS for both client and server verification.
		/// </para>
		/// <para>
		/// It does however define a bootstrapping mode where if the client does not have the necessary ca certificates to
		/// validate the server it can defer to an external source, such as a human, to formally accept the ca certs.
		/// </para>
		/// <para>
		/// If callers are using bootstrapping they must examine the CACertsResponse and validate it externally.
		/// 
		/// </para>
		/// </summary>
		/// <returns> A store of X509Certificates. </returns>
		public virtual CACertsResponse getCACerts()
		{
			ESTResponse resp = null;
			Exception finalThrowable = null;
			CACertsResponse caCertsResponse = null;
			URL url = null;
			bool failedBeforeClose = false;
			try
			{
				url = new URL(server + CACERTS);

				ESTClient client = clientProvider.makeClient();
				ESTRequest req = (new ESTRequestBuilder("GET", url)).withClient(client).build();
				resp = client.doRequest(req);

				Store<X509CertificateHolder> caCerts = null;
				Store<X509CRLHolder> crlHolderStore = null;


				if (resp.getStatusCode() == 200)
				{
					if (!"application/pkcs7-mime".Equals(resp.getHeaders().getFirstValue("Content-Type")))
					{
						string j = !string.ReferenceEquals(resp.getHeaders().getFirstValue("Content-Type"), null) ? " got " + resp.getHeaders().getFirstValue("Content-Type") : " but was not present.";
						throw new ESTException(("Response : " + url.ToString() + "Expecting application/pkcs7-mime ") + j, null, resp.getStatusCode(), resp.getInputStream());
					}

					try
					{
						if (resp.getContentLength() != null && resp.getContentLength() > 0)
						{
							ASN1InputStream ain = new ASN1InputStream(resp.getInputStream());
							SimplePKIResponse spkr = new SimplePKIResponse(ContentInfo.getInstance((ASN1Sequence)ain.readObject()));
							caCerts = spkr.getCertificates();
							crlHolderStore = spkr.getCRLs();
						}
					}
					catch (Exception ex)
					{
						throw new ESTException("Decoding CACerts: " + url.ToString() + " " + ex.Message, ex, resp.getStatusCode(), resp.getInputStream());
					}

				}
				else if (resp.getStatusCode() != 204) // 204 are No Content
				{
					throw new ESTException("Get CACerts: " + url.ToString(), null, resp.getStatusCode(), resp.getInputStream());
				}

				caCertsResponse = new CACertsResponse(caCerts, crlHolderStore, req, resp.getSource(), clientProvider.isTrusted());

			}
			catch (Exception t)
			{
				failedBeforeClose = true;
				if (t is ESTException)
				{
					throw (ESTException)t;
				}
				else
				{
					throw new ESTException(t.Message, t);
				}
			}
			finally
			{
				if (resp != null)
				{
					try
					{
						resp.close();
					}
					catch (Exception t)
					{
						finalThrowable = t;
					}
				}
			}

			if (finalThrowable != null)
			{
				if (finalThrowable is ESTException)
				{
					throw finalThrowable;
				}
				throw new ESTException("Get CACerts: " + url.ToString(), finalThrowable, resp.getStatusCode(), null);
			}

			return caCertsResponse;


		}

		/// <summary>
		/// Reissue an existing request where the server had previously returned a 202.
		/// </summary>
		/// <param name="priorResponse"> The prior response. </param>
		/// <returns> A new ESTEnrollmentResponse </returns>
		/// <exception cref="Exception"> </exception>
		public virtual EnrollmentResponse simpleEnroll(EnrollmentResponse priorResponse)
		{
			if (!clientProvider.isTrusted())
			{
				throw new IllegalStateException("No trust anchors.");
			}

			ESTResponse resp = null;

			try
			{
				ESTClient client = clientProvider.makeClient();
				resp = client.doRequest((new ESTRequestBuilder(priorResponse.getRequestToRetry())).withClient(client).build());
				return handleEnrollResponse(resp);
			}
			catch (Exception t)
			{
				if (t is ESTException)
				{
					throw (ESTException)t;
				}
				else
				{
					throw new ESTException(t.Message, t);
				}
			}
			finally
			{
				if (resp != null)
				{
					resp.close();
				}
			}
		}

		/// <summary>
		/// Perform a simple enrollment operation.
		/// <para>
		/// This method accepts an ESPHttpAuth instance to provide basic or digest authentication.
		/// </para>
		/// <para>
		/// If authentication is to be performed as part of TLS then this instances client keystore and their keystore
		/// password need to be specified.
		/// 
		/// </para>
		/// </summary>
		/// <param name="certificationRequest"> The certification request. </param>
		/// <param name="auth">                 The http auth provider, basic auth or digest auth, can be null. </param>
		/// <returns> The enrolled certificate. </returns>
		public virtual EnrollmentResponse simpleEnroll(bool reenroll, PKCS10CertificationRequest certificationRequest, ESTAuth auth)
		{
			if (!clientProvider.isTrusted())
			{
				throw new IllegalStateException("No trust anchors.");
			}

			ESTResponse resp = null;
			try
			{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final byte[] data = annotateRequest(certificationRequest.getEncoded()).getBytes();
				byte[] data = annotateRequest(certificationRequest.getEncoded()).GetBytes();

				URL url = new URL(server + (reenroll ? SIMPLE_REENROLL : SIMPLE_ENROLL));


				ESTClient client = clientProvider.makeClient();
				ESTRequestBuilder req = (new ESTRequestBuilder("POST", url)).withData(data).withClient(client);

				req.addHeader("Content-Type", "application/pkcs10");
				req.addHeader("Content-Length", "" + data.Length);
				req.addHeader("Content-Transfer-Encoding", "base64");

				if (auth != null)
				{
					auth.applyAuth(req);
				}

				resp = client.doRequest(req.build());

				return handleEnrollResponse(resp);

			}
			catch (Exception t)
			{
				if (t is ESTException)
				{
					throw (ESTException)t;
				}
				else
				{
					throw new ESTException(t.Message, t);
				}
			}
			finally
			{
				if (resp != null)
				{
					resp.close();
				}
			}

		}


		/// <summary>
		/// Implements Enroll with PoP.
		/// Request will have the tls-unique attribute added to it before it is signed and completed.
		/// </summary>
		/// <param name="reEnroll">      True = re enroll. </param>
		/// <param name="builder">       The request builder. </param>
		/// <param name="contentSigner"> The content signer. </param>
		/// <param name="auth">          Auth modes. </param>
		/// <returns> Enrollment response. </returns>
		/// <exception cref="IOException"> </exception>
//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public EnrollmentResponse simpleEnrollPoP(boolean reEnroll, final org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder builder, final org.bouncycastle.operator.ContentSigner contentSigner, ESTAuth auth) throws java.io.IOException
		public virtual EnrollmentResponse simpleEnrollPoP(bool reEnroll, PKCS10CertificationRequestBuilder builder, ContentSigner contentSigner, ESTAuth auth)
		{
			if (!clientProvider.isTrusted())
			{
				throw new IllegalStateException("No trust anchors.");
			}

			ESTResponse resp = null;
			try
			{
				URL url = new URL(server + (reEnroll ? SIMPLE_REENROLL : SIMPLE_ENROLL));
				ESTClient client = clientProvider.makeClient();

				//
				// Connect supplying a source listener.
				// The source listener is responsible for completing the PCS10 Cert request and encoding it.
				//
				ESTRequestBuilder reqBldr = (new ESTRequestBuilder("POST", url)).withClient(client).withConnectionListener(new ESTSourceConnectionListenerAnonymousInnerClass(this, builder, contentSigner));

				if (auth != null)
				{
					auth.applyAuth(reqBldr);
				}

				resp = client.doRequest(reqBldr.build());

				return handleEnrollResponse(resp);

			}
			catch (Exception t)
			{
				if (t is ESTException)
				{
					throw (ESTException)t;
				}
				else
				{
					throw new ESTException(t.Message, t);
				}
			}
			finally
			{
				if (resp != null)
				{
					resp.close();
				}
			}

		}

		public class ESTSourceConnectionListenerAnonymousInnerClass : ESTSourceConnectionListener
		{
			private readonly ESTService outerInstance;

			private PKCS10CertificationRequestBuilder builder;
			private ContentSigner contentSigner;

			public ESTSourceConnectionListenerAnonymousInnerClass(ESTService outerInstance, PKCS10CertificationRequestBuilder builder, ContentSigner contentSigner)
			{
				this.outerInstance = outerInstance;
				this.builder = builder;
				this.contentSigner = contentSigner;
			}

			public ESTRequest onConnection(Source source, ESTRequest request)
			{
				//
				// Add challenge password from tls unique
				//

				if (source is TLSUniqueProvider && ((TLSUniqueProvider)source).isTLSUniqueAvailable())
				{
					PKCS10CertificationRequestBuilder localBuilder = new PKCS10CertificationRequestBuilder(builder);

					ByteArrayOutputStream bos = new ByteArrayOutputStream();
					byte[] tlsUnique = ((TLSUniqueProvider)source).getTLSUnique();

					localBuilder.setAttribute(PKCSObjectIdentifiers_Fields.pkcs_9_at_challengePassword, new DERPrintableString(Base64.toBase64String(tlsUnique)));
					bos.write(outerInstance.annotateRequest(localBuilder.build(contentSigner).getEncoded()).GetBytes());
					bos.flush();

					ESTRequestBuilder reqBuilder = (new ESTRequestBuilder(request)).withData(bos.toByteArray());

					reqBuilder.setHeader("Content-Type", "application/pkcs10");
					reqBuilder.setHeader("Content-Transfer-Encoding", "base64");
					reqBuilder.setHeader("Content-Length", Convert.ToString(bos.size()));

					return reqBuilder.build();
				}
				else
				{
					throw new IOException("Source does not supply TLS unique.");
				}
			}
		}


		/// <summary>
		/// Handles the enroll response, deals with status codes and setting of delays.
		/// </summary>
		/// <param name="resp"> The response. </param>
		/// <returns> An EnrollmentResponse. </returns>
		/// <exception cref="IOException"> </exception>
		public virtual EnrollmentResponse handleEnrollResponse(ESTResponse resp)
		{

			ESTRequest req = resp.getOriginalRequest();
			Store<X509CertificateHolder> enrolled = null;
			if (resp.getStatusCode() == 202)
			{
				// Received but not ready.
				string rt = resp.getHeader("Retry-After");

				if (string.ReferenceEquals(rt, null))
				{
					throw new ESTException("Got Status 202 but not Retry-After header from: " + req.getURL().ToString());
				}

				long notBefore = -1;


				try
				{
					notBefore = System.currentTimeMillis() + (long.Parse(rt) * 1000);
				}
				catch (NumberFormatException)
				{
					try
					{
						SimpleDateFormat dateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
						dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
						notBefore = dateFormat.parse(rt).getTime();
					}
					catch (Exception ex)
					{
						throw new ESTException("Unable to parse Retry-After header:" + req.getURL().ToString() + " " + ex.Message, null, resp.getStatusCode(), resp.getInputStream());
					}
				}

				return new EnrollmentResponse(null, notBefore, req, resp.getSource());

			}
			else if (resp.getStatusCode() == 200)
			{
				ASN1InputStream ain = new ASN1InputStream(resp.getInputStream());
				SimplePKIResponse spkr = null;
				try
				{
					spkr = new SimplePKIResponse(ContentInfo.getInstance(ain.readObject()));
				}
				catch (CMCException e)
				{
					throw new ESTException(e.Message, e.InnerException);
				}
				enrolled = spkr.getCertificates();
				return new EnrollmentResponse(enrolled, -1, null, resp.getSource());
			}

			throw new ESTException("Simple Enroll: " + req.getURL().ToString(), null, resp.getStatusCode(), resp.getInputStream());

		}

		/// <summary>
		/// Fetch he CSR Attributes from the server.
		/// </summary>
		/// <returns> A CSRRequestResponse with the attributes. </returns>
		/// <exception cref="ESTException"> </exception>
		public virtual CSRRequestResponse getCSRAttributes()
		{

			if (!clientProvider.isTrusted())
			{
				throw new IllegalStateException("No trust anchors.");
			}

			ESTResponse resp = null;
			CSRAttributesResponse response = null;
			Exception finalThrowable = null;
			URL url = null;
			try
			{
				url = new URL(server + CSRATTRS);

				ESTClient client = clientProvider.makeClient();
				ESTRequest req = (new ESTRequestBuilder("GET", url)).withClient(client).build(); //    new ESTRequest("GET", url, null);
				resp = client.doRequest(req);


				switch (resp.getStatusCode())
				{
				case 200:
					try
					{
						if (resp.getContentLength() != null && resp.getContentLength() > 0)
						{
							ASN1InputStream ain = new ASN1InputStream(resp.getInputStream());
							ASN1Sequence seq = (ASN1Sequence)ain.readObject();
							response = new CSRAttributesResponse(CsrAttrs.getInstance(seq));
						}
					}
					catch (Exception ex)
					{
						throw new ESTException("Decoding CACerts: " + url.ToString() + " " + ex.Message, ex, resp.getStatusCode(), resp.getInputStream());
					}

					break;
				case 204:
					response = null;
					break;
				case 404:
					response = null;
					break;
				default:
					throw new ESTException("CSR Attribute request: " + req.getURL().ToString(), null, resp.getStatusCode(), resp.getInputStream());
				}
			}
			catch (Exception t)
			{

				if (t is ESTException)
				{
					throw (ESTException)t;
				}
				else
				{
					throw new ESTException(t.Message, t);
				}
			}
			finally
			{
				if (resp != null)
				{
					try
					{
						resp.close();
					}
					catch (Exception ex)
					{
						finalThrowable = ex;
					}
				}
			}

			if (finalThrowable != null)
			{
				if (finalThrowable is ESTException)
				{
					throw (ESTException)finalThrowable;
				}
				throw new ESTException(finalThrowable.Message, finalThrowable, resp.getStatusCode(), null);
			}

			return new CSRRequestResponse(response, resp.getSource());
		}

		private string annotateRequest(byte[] data)
		{
			int i = 0;
			StringWriter sw = new StringWriter();
			PrintWriter pw = new PrintWriter(sw);
			// pw.print("-----BEGIN CERTIFICATE REQUEST-----\n");
			do
			{
				if (i + 48 < data.Length)
				{
					pw.print(Base64.toBase64String(data, i, 48));
					i += 48;
				}
				else
				{
					pw.print(Base64.toBase64String(data, i, data.Length - i));
					i = data.Length;
				}
				pw.print('\n');
			} while (i < data.Length);
			//  pw.print("-----END CERTIFICATE REQUEST-----\n");
			pw.flush();
			return sw.ToString();
		}


		private string verifyLabel(string label)
		{
			while (label.EndsWith("/", StringComparison.Ordinal) && label.Length > 0)
			{
				label = label.Substring(0, label.Length - 1);
			}

			while (label.StartsWith("/", StringComparison.Ordinal) && label.Length > 0)
			{
				label = label.Substring(1);
			}

			if (label.Length == 0)
			{
				throw new IllegalArgumentException("Label set but after trimming '/' is not zero length string.");
			}

			if (!pathInvalid.matcher(label).matches())
			{
				throw new IllegalArgumentException("Server path " + label + " contains invalid characters");
			}

			if (illegalParts.contains(label))
			{
				throw new IllegalArgumentException("Label " + label + " is a reserved path segment.");
			}

			return label;

		}


		private string verifyServer(string server)
		{
			try
			{

				while (server.EndsWith("/", StringComparison.Ordinal) && server.Length > 0)
				{
					server = server.Substring(0, server.Length - 1);
				}

				if (server.Contains("://"))
				{
					throw new IllegalArgumentException("Server contains scheme, must only be <dnsname/ipaddress>:port, https:// will be added arbitrarily.");
				}

				URL u = new URL("https://" + server);
				if (u.getPath().length() == 0 || u.getPath().Equals("/"))
				{
					return server;
				}

				throw new IllegalArgumentException("Server contains path, must only be <dnsname/ipaddress>:port, a path of '/.well-known/est/<label>' will be added arbitrarily.");

			}
			catch (Exception ex)
			{
				if (ex is IllegalArgumentException)
				{
					throw (IllegalArgumentException)ex;
				}
				throw new IllegalArgumentException("Scheme and host is invalid: " + ex.Message, ex);
			}

		}
	}

}