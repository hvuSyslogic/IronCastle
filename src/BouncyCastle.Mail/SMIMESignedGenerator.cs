using org.bouncycastle.asn1.oiw;
using org.bouncycastle.asn1.pkcs;
using org.bouncycastle.asn1.nist;
using org.bouncycastle.asn1.cryptopro;
using org.bouncycastle.asn1.teletrust;
using org.bouncycastle.asn1.x9;
using org.bouncycastle.asn1.rosstandart;

namespace org.bouncycastle.mail.smime
{


	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using CryptoProObjectIdentifiers = org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
	using NISTObjectIdentifiers = org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using PKCSObjectIdentifiers = org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
	using RosstandartObjectIdentifiers = org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
	using TeleTrusTObjectIdentifiers = org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
	using X9ObjectIdentifiers = org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
	using CMSAlgorithm = org.bouncycastle.cms.CMSAlgorithm;
	using CMSException = org.bouncycastle.cms.CMSException;
	using CMSSignedDataStreamGenerator = org.bouncycastle.cms.CMSSignedDataStreamGenerator;
	using SignerInfoGenerator = org.bouncycastle.cms.SignerInfoGenerator;
	using SignerInformation = org.bouncycastle.cms.SignerInformation;
	using SignerInformationStore = org.bouncycastle.cms.SignerInformationStore;
	using CRLFOutputStream = org.bouncycastle.mail.smime.util.CRLFOutputStream;
	using Store = org.bouncycastle.util.Store;

	/// <summary>
	/// general class for generating a pkcs7-signature message.
	/// <para>
	/// A simple example of usage.
	/// 
	/// <pre>
	///      X509Certificate signCert = ...
	///      KeyPair         signKP = ...
	/// 
	///      List certList = new ArrayList();
	/// 
	///      certList.add(signCert);
	/// 
	///      Store certs = new JcaCertStore(certList);
	/// 
	///      SMIMESignedGenerator gen = new SMIMESignedGenerator();
	/// 
	///      gen.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").build("SHA1withRSA", signKP.getPrivate(), signCert));
	/// 
	///      gen.addCertificates(certs);
	/// 
	///      MimeMultipart       smime = fact.generate(content);
	/// </pre>
	/// </para>
	/// <para>
	/// Note 1: if you are using this class with AS2 or some other protocol
	/// that does not use "7bit" as the default content transfer encoding you
	/// will need to use the constructor that allows you to specify the default
	/// content transfer encoding, such as "binary".
	/// </para>
	/// <para>
	/// Note 2: between RFC 3851 and RFC 5751 the values used in the micalg parameter
	/// for signed messages changed. We will accept both, but the default is now to use
	/// RFC 5751. In the event you are dealing with an older style system you will also need
	/// to use a constructor that sets the micalgs table and call it with RFC3851_MICALGS.
	/// </para>
	/// </summary>
	public class SMIMESignedGenerator : SMIMEGenerator
	{
		public static readonly string DIGEST_SHA1 = OIWObjectIdentifiers_Fields.idSHA1.getId();
		public static readonly string DIGEST_MD5 = PKCSObjectIdentifiers_Fields.md5.getId();
		public static readonly string DIGEST_SHA224 = NISTObjectIdentifiers_Fields.id_sha224.getId();
		public static readonly string DIGEST_SHA256 = NISTObjectIdentifiers_Fields.id_sha256.getId();
		public static readonly string DIGEST_SHA384 = NISTObjectIdentifiers_Fields.id_sha384.getId();
		public static readonly string DIGEST_SHA512 = NISTObjectIdentifiers_Fields.id_sha512.getId();
		public static readonly string DIGEST_GOST3411 = CryptoProObjectIdentifiers_Fields.gostR3411.getId();
		public static readonly string DIGEST_RIPEMD128 = TeleTrusTObjectIdentifiers_Fields.ripemd128.getId();
		public static readonly string DIGEST_RIPEMD160 = TeleTrusTObjectIdentifiers_Fields.ripemd160.getId();
		public static readonly string DIGEST_RIPEMD256 = TeleTrusTObjectIdentifiers_Fields.ripemd256.getId();

		public static readonly string ENCRYPTION_RSA = PKCSObjectIdentifiers_Fields.rsaEncryption.getId();
		public static readonly string ENCRYPTION_DSA = X9ObjectIdentifiers_Fields.id_dsa_with_sha1.getId();
		public static readonly string ENCRYPTION_ECDSA = X9ObjectIdentifiers_Fields.ecdsa_with_SHA1.getId();
		public static readonly string ENCRYPTION_RSA_PSS = PKCSObjectIdentifiers_Fields.id_RSASSA_PSS.getId();
		public static readonly string ENCRYPTION_GOST3410 = CryptoProObjectIdentifiers_Fields.gostR3410_94.getId();
		public static readonly string ENCRYPTION_ECGOST3410 = CryptoProObjectIdentifiers_Fields.gostR3410_2001.getId();
		public static readonly string ENCRYPTION_ECGOST3410_2012_256 = RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_256.getId();
		public static readonly string ENCRYPTION_ECGOST3410_2012_512 = RosstandartObjectIdentifiers_Fields.id_tc26_gost_3410_12_512.getId();

		private const string CERTIFICATE_MANAGEMENT_CONTENT = "application/pkcs7-mime; name=smime.p7c; smime-type=certs-only";
		private const string DETACHED_SIGNATURE_TYPE = "application/pkcs7-signature; name=smime.p7s; smime-type=signed-data";
		private const string ENCAPSULATED_SIGNED_CONTENT_TYPE = "application/pkcs7-mime; name=smime.p7m; smime-type=signed-data";

		public static readonly Map RFC3851_MICALGS;
		public static readonly Map RFC5751_MICALGS;
		public static readonly Map STANDARD_MICALGS;

		private static MailcapCommandMap addCommands(MailcapCommandMap mc)
		{
			mc.addMailcap("application/pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_signature");
			mc.addMailcap("application/pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.pkcs7_mime");
			mc.addMailcap("application/x-pkcs7-signature;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_signature");
			mc.addMailcap("application/x-pkcs7-mime;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.x_pkcs7_mime");
			mc.addMailcap("multipart/signed;; x-java-content-handler=org.bouncycastle.mail.smime.handlers.multipart_signed");

			return mc;
		}

		static SMIMESignedGenerator()
		{
			AccessController.doPrivileged(new PrivilegedActionAnonymousInnerClass());

			Map stdMicAlgs = new HashMap();

			stdMicAlgs.put(CMSAlgorithm.MD5, "md5");
			stdMicAlgs.put(CMSAlgorithm.SHA1, "sha-1");
			stdMicAlgs.put(CMSAlgorithm.SHA224, "sha-224");
			stdMicAlgs.put(CMSAlgorithm.SHA256, "sha-256");
			stdMicAlgs.put(CMSAlgorithm.SHA384, "sha-384");
			stdMicAlgs.put(CMSAlgorithm.SHA512, "sha-512");
			stdMicAlgs.put(CMSAlgorithm.GOST3411, "gostr3411-94");
			stdMicAlgs.put(CMSAlgorithm.GOST3411_2012_256, "gostr3411-2012-256");
			stdMicAlgs.put(CMSAlgorithm.GOST3411_2012_512, "gostr3411-2012-512");

			RFC5751_MICALGS = Collections.unmodifiableMap(stdMicAlgs);

			Map oldMicAlgs = new HashMap();

			oldMicAlgs.put(CMSAlgorithm.MD5, "md5");
			oldMicAlgs.put(CMSAlgorithm.SHA1, "sha1");
			oldMicAlgs.put(CMSAlgorithm.SHA224, "sha224");
			oldMicAlgs.put(CMSAlgorithm.SHA256, "sha256");
			oldMicAlgs.put(CMSAlgorithm.SHA384, "sha384");
			oldMicAlgs.put(CMSAlgorithm.SHA512, "sha512");
			oldMicAlgs.put(CMSAlgorithm.GOST3411, "gostr3411-94");
			oldMicAlgs.put(CMSAlgorithm.GOST3411_2012_256, "gostr3411-2012-256");
			oldMicAlgs.put(CMSAlgorithm.GOST3411_2012_512, "gostr3411-2012-512");

			RFC3851_MICALGS = Collections.unmodifiableMap(oldMicAlgs);

			STANDARD_MICALGS = RFC5751_MICALGS;
		}

		public class PrivilegedActionAnonymousInnerClass : PrivilegedAction
		{
			public object run()
			{
				CommandMap commandMap = CommandMap.getDefaultCommandMap();

				if (commandMap is MailcapCommandMap)
				{
					CommandMap.setDefaultCommandMap(addCommands((MailcapCommandMap)commandMap));
				}

				return null;
			}
		}

		private readonly string defaultContentTransferEncoding;
		private readonly Map micAlgs;

		private List _certStores = new ArrayList();
		private List certStores = new ArrayList();
		private List crlStores = new ArrayList();
		private List attrCertStores = new ArrayList();
		private List signerInfoGens = new ArrayList();
		private List _signers = new ArrayList();
		private List _oldSigners = new ArrayList();
		private List _attributeCerts = new ArrayList();
		private Map _digests = new HashMap();

		/// <summary>
		/// base constructor - default content transfer encoding 7bit
		/// </summary>
		public SMIMESignedGenerator() : this("7bit", STANDARD_MICALGS)
		{
		}

		/// <summary>
		/// base constructor - default content transfer encoding explicitly set
		/// </summary>
		/// <param name="defaultContentTransferEncoding"> new default to use. </param>
		public SMIMESignedGenerator(string defaultContentTransferEncoding) : this(defaultContentTransferEncoding, STANDARD_MICALGS)
		{
		}

		/// <summary>
		/// base constructor - default content transfer encoding explicitly set
		/// </summary>
		/// <param name="micAlgs"> a map of ANS1ObjectIdentifiers to strings hash algorithm names. </param>
		public SMIMESignedGenerator(Map micAlgs) : this("7bit", micAlgs)
		{
		}

		/// <summary>
		/// base constructor - default content transfer encoding explicitly set
		/// </summary>
		/// <param name="defaultContentTransferEncoding"> new default to use. </param>
		/// <param name="micAlgs"> a map of ANS1ObjectIdentifiers to strings hash algorithm names. </param>
		public SMIMESignedGenerator(string defaultContentTransferEncoding, Map micAlgs)
		{
			this.defaultContentTransferEncoding = defaultContentTransferEncoding;
			this.micAlgs = micAlgs;
		}

		/// <summary>
		/// Add a store of precalculated signers to the generator.
		/// </summary>
		/// <param name="signerStore"> store of signers </param>
		public virtual void addSigners(SignerInformationStore signerStore)
		{
			Iterator it = signerStore.getSigners().iterator();

			while (it.hasNext())
			{
				_oldSigners.add(it.next());
			}
		}

		/// 
		/// <param name="sigInfoGen"> </param>
		public virtual void addSignerInfoGenerator(SignerInfoGenerator sigInfoGen)
		{
			signerInfoGens.add(sigInfoGen);
		}

		public virtual void addCertificates(Store certStore)
		{
			certStores.add(certStore);
		}

		public virtual void addCRLs(Store crlStore)
		{
			crlStores.add(crlStore);
		}

		public virtual void addAttributeCertificates(Store certStore)
		{
			attrCertStores.add(certStore);
		}

		private void addHashHeader(StringBuffer header, List signers)
		{
			int count = 0;

			//
			// build the hash header
			//
			Iterator it = signers.iterator();
			Set micAlgSet = new TreeSet();

			while (it.hasNext())
			{
				object signer = it.next();
				ASN1ObjectIdentifier digestOID;

				if (signer is SignerInformation)
				{
					digestOID = ((SignerInformation)signer).getDigestAlgorithmID().getAlgorithm();
				}
				else
				{
					digestOID = ((SignerInfoGenerator)signer).getDigestAlgorithm().getAlgorithm();
				}

				string micAlg = (string)micAlgs.get(digestOID);

				if (string.ReferenceEquals(micAlg, null))
				{
					micAlgSet.add("unknown");
				}
				else
				{
					micAlgSet.add(micAlg);
				}
			}

			it = micAlgSet.iterator();

			while (it.hasNext())
			{
				string alg = (string)it.next();

				if (count == 0)
				{
					if (micAlgSet.size() != 1)
					{
						header.append(@"; micalg=""");
					}
					else
					{
						header.append("; micalg=");
					}
				}
				else
				{
					header.append(',');
				}

				header.append(alg);

				count++;
			}

			if (count != 0)
			{
				if (micAlgSet.size() != 1)
				{
					header.append('\"');
				}
			}
		}

		private MimeMultipart make(MimeBodyPart content)
		{
			try
			{
				MimeBodyPart sig = new MimeBodyPart();

				sig.setContent(new ContentSigner(this, content, false), DETACHED_SIGNATURE_TYPE);
				sig.addHeader("Content-Type", DETACHED_SIGNATURE_TYPE);
				sig.addHeader("Content-Disposition", @"attachment; filename=""smime.p7s""");
				sig.addHeader("Content-Description", "S/MIME Cryptographic Signature");
				sig.addHeader("Content-Transfer-Encoding", encoding);

				//
				// build the multipart header
				//
				StringBuffer header = new StringBuffer(@"signed; protocol=""application/pkcs7-signature""");

				List allSigners = new ArrayList(_signers);

				allSigners.addAll(_oldSigners);

				allSigners.addAll(signerInfoGens);

				addHashHeader(header, allSigners);

				MimeMultipart mm = new MimeMultipart(header.ToString());

				mm.addBodyPart(content);
				mm.addBodyPart(sig);

				return mm;
			}
			catch (MessagingException e)
			{
				throw new SMIMEException("exception putting multi-part together.", e);
			}
		}

		/*
		 * at this point we expect our body part to be well defined - generate with data in the signature
		 */
		private MimeBodyPart makeEncapsulated(MimeBodyPart content)
		{
			try
			{
				MimeBodyPart sig = new MimeBodyPart();

				sig.setContent(new ContentSigner(this, content, true), ENCAPSULATED_SIGNED_CONTENT_TYPE);
				sig.addHeader("Content-Type", ENCAPSULATED_SIGNED_CONTENT_TYPE);
				sig.addHeader("Content-Disposition", @"attachment; filename=""smime.p7m""");
				sig.addHeader("Content-Description", "S/MIME Cryptographic Signed Data");
				sig.addHeader("Content-Transfer-Encoding", encoding);

				return sig;
			}
			catch (MessagingException e)
			{
				throw new SMIMEException("exception putting body part together.", e);
			}
		}

		/// <summary>
		/// Return a map of oids and byte arrays representing the digests calculated on the content during
		/// the last generate.
		/// </summary>
		/// <returns> a map of oids (as String objects) and byte[] representing digests. </returns>
		public virtual Map getGeneratedDigests()
		{
			return new HashMap(_digests);
		}

		public virtual MimeMultipart generate(MimeBodyPart content)
		{
			return make(makeContentBodyPart(content));
		}

		public virtual MimeMultipart generate(MimeMessage message)
		{
			try
			{
				message.saveChanges(); // make sure we're up to date.
			}
			catch (MessagingException e)
			{
				throw new SMIMEException("unable to save message", e);
			}

			return make(makeContentBodyPart(message));
		}

		/// <summary>
		/// generate a signed message with encapsulated content
		/// <para>
		/// Note: doing this is strongly <b>not</b> recommended as it means a
		/// recipient of the message will have to be able to read the signature to read the
		/// message.
		/// </para>
		/// </summary>
		public virtual MimeBodyPart generateEncapsulated(MimeBodyPart content)
		{
			return makeEncapsulated(makeContentBodyPart(content));
		}

		public virtual MimeBodyPart generateEncapsulated(MimeMessage message)
		{
			try
			{
				message.saveChanges(); // make sure we're up to date.
			}
			catch (MessagingException e)
			{
				throw new SMIMEException("unable to save message", e);
			}

			return makeEncapsulated(makeContentBodyPart(message));
		}

	   /// <summary>
	   /// Creates a certificate management message which is like a signed message with no content
	   /// or signers but that still carries certificates and CRLs.
	   /// </summary>
	   /// <returns> a MimeBodyPart containing the certs and CRLs. </returns>
		public virtual MimeBodyPart generateCertificateManagement()
		{
			try
			{
				MimeBodyPart sig = new MimeBodyPart();

				sig.setContent(new ContentSigner(this, null, true), CERTIFICATE_MANAGEMENT_CONTENT);
				sig.addHeader("Content-Type", CERTIFICATE_MANAGEMENT_CONTENT);
				sig.addHeader("Content-Disposition", @"attachment; filename=""smime.p7c""");
				sig.addHeader("Content-Description", "S/MIME Certificate Management Message");
				sig.addHeader("Content-Transfer-Encoding", encoding);

				return sig;
			}
			catch (MessagingException e)
			{
				throw new SMIMEException("exception putting body part together.", e);
			}
		}

		public class ContentSigner : SMIMEStreamingProcessor
		{
			private readonly SMIMESignedGenerator outerInstance;

			internal readonly MimeBodyPart content;
			internal readonly bool encapsulate;
			internal readonly bool noProvider;

			public ContentSigner(SMIMESignedGenerator outerInstance, MimeBodyPart content, bool encapsulate)
			{
				this.outerInstance = outerInstance;
				this.content = content;
				this.encapsulate = encapsulate;
				this.noProvider = true;
			}

			public virtual CMSSignedDataStreamGenerator getGenerator()
			{
				CMSSignedDataStreamGenerator gen = new CMSSignedDataStreamGenerator();

				for (Iterator it = outerInstance.certStores.iterator(); it.hasNext();)
				{
					gen.addCertificates((Store)it.next());
				}

				for (Iterator it = outerInstance.crlStores.iterator(); it.hasNext();)
				{
					gen.addCRLs((Store)it.next());
				}

				for (Iterator it = outerInstance.attrCertStores.iterator(); it.hasNext();)
				{
					gen.addAttributeCertificates((Store)it.next());
				}

				for (Iterator it = outerInstance.signerInfoGens.iterator(); it.hasNext();)
				{
					gen.addSignerInfoGenerator((SignerInfoGenerator)it.next());
				}

				gen.addSigners(new SignerInformationStore(outerInstance._oldSigners));

				return gen;
			}

			public virtual void writeBodyPart(OutputStream @out, MimeBodyPart bodyPart)
			{
				if (SMIMEUtil.isMultipartContent(bodyPart))
				{
					object content = bodyPart.getContent();
					Multipart mp;
					if (content is Multipart)
					{
						mp = (Multipart)content;
					}
					else
					{
						mp = new MimeMultipart(bodyPart.getDataHandler().getDataSource());
					}

					ContentType contentType = new ContentType(mp.getContentType());
					string boundary = "--" + contentType.getParameter("boundary");

					SMIMEUtil.LineOutputStream lOut = new SMIMEUtil.LineOutputStream(@out);

					Enumeration headers = bodyPart.getAllHeaderLines();
					while (headers.hasMoreElements())
					{
						lOut.writeln((string)headers.nextElement());
					}

					lOut.writeln(); // CRLF separator

					SMIMEUtil.outputPreamble(lOut, bodyPart, boundary);

					for (int i = 0; i < mp.getCount(); i++)
					{
						lOut.writeln(boundary);
						writeBodyPart(@out, (MimeBodyPart)mp.getBodyPart(i));
						lOut.writeln(); // CRLF terminator
					}

					lOut.writeln(boundary + "--");
				}
				else
				{
					if (SMIMEUtil.isCanonicalisationRequired(bodyPart, outerInstance.defaultContentTransferEncoding))
					{
						@out = new CRLFOutputStream(@out);
					}

					bodyPart.writeTo(@out);
				}
			}

			public virtual void write(OutputStream @out)
			{
				try
				{
					CMSSignedDataStreamGenerator gen = getGenerator();

					OutputStream signingStream = gen.open(@out, encapsulate);

					if (content != null)
					{
						if (!encapsulate)
						{
							writeBodyPart(signingStream, content);
						}
						else
						{
							CommandMap commandMap = CommandMap.getDefaultCommandMap();

							if (commandMap is MailcapCommandMap)
							{
								content.getDataHandler().setCommandMap(addCommands((MailcapCommandMap)commandMap));
							}

							content.writeTo(signingStream);
						}
					}

					signingStream.close();

					outerInstance._digests = gen.getGeneratedDigests();
				}
				catch (MessagingException e)
				{
					throw new IOException(e.ToString());
				}
				catch (CMSException e)
				{
					throw new IOException(e.ToString());
				}
			}
		}
	}

}