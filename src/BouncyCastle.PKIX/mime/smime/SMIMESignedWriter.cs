namespace org.bouncycastle.mime.smime
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;
	using CMSAlgorithm = org.bouncycastle.cms.CMSAlgorithm;
	using CMSException = org.bouncycastle.cms.CMSException;
	using CMSSignedDataStreamGenerator = org.bouncycastle.cms.CMSSignedDataStreamGenerator;
	using SignerInfoGenerator = org.bouncycastle.cms.SignerInfoGenerator;
	using Base64OutputStream = org.bouncycastle.mime.encoding.Base64OutputStream;
	using Store = org.bouncycastle.util.Store;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Writer for SMIME Signed objects.
	/// </summary>
	public class SMIMESignedWriter : MimeWriter
	{
		public static readonly Map RFC3851_MICALGS;
		public static readonly Map RFC5751_MICALGS;
		public static readonly Map STANDARD_MICALGS;

		static SMIMESignedWriter()
		{
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
				detHeaders = new string[] {"Content-Type"};

				detValues = new string[] {@"multipart/signed; protocol=""application/pkcs7-signature"""};

				encHeaders = new string[] {"Content-Type", "Content-Disposition", "Content-Transfer-Encoding", "Content-Description"};

				encValues = new string[] {@"application/pkcs7-mime; name=""smime.p7m""; smime-type=enveloped-data", @"attachment; filename=""smime.p7m""", "base64", "S/MIME Signed Message"};
		}

		public class Builder
		{
			internal static readonly string[] detHeaders;
			internal static readonly string[] detValues;
			internal static readonly string[] encHeaders;
			internal static readonly string[] encValues;


			internal readonly CMSSignedDataStreamGenerator sigGen = new CMSSignedDataStreamGenerator();
			internal readonly Map<string, string> extraHeaders = new LinkedHashMap<string, string>();
			internal readonly bool encapsulated;
			internal readonly Map micAlgs = STANDARD_MICALGS;

			internal string contentTransferEncoding = "base64";

			public Builder() : this(false)
			{
			}

			public Builder(bool encapsulated)
			{
				this.encapsulated = encapsulated;
			}

			/// <summary>
			/// Specify a MIME header (name, value) pair for this builder. If the headerName already exists it will
			/// be overridden.
			/// </summary>
			/// <param name="headerName">  name of the MIME header. </param>
			/// <param name="headerValue"> value of the MIME header. </param>
			/// <returns> the current Builder instance. </returns>
			public virtual Builder withHeader(string headerName, string headerValue)
			{
				this.extraHeaders.put(headerName, headerValue);

				return this;
			}

			public virtual Builder addCertificate(X509CertificateHolder certificate)
			{
				this.sigGen.addCertificate(certificate);

				return this;
			}

			public virtual Builder addCertificates(Store certificates)
			{
				this.sigGen.addCertificates(certificates);

				return this;
			}

			/// <summary>
			/// Add a generator to produce the signer info required.
			/// </summary>
			/// <param name="signerGenerator"> a generator for a signer info object. </param>
			/// <returns> the current Builder instance. </returns>
			public virtual Builder addSignerInfoGenerator(SignerInfoGenerator signerGenerator)
			{
				this.sigGen.addSignerInfoGenerator(signerGenerator);

				return this;
			}

			public virtual SMIMESignedWriter build(OutputStream mimeOut)
			{
				Map<string, string> headers = new LinkedHashMap<string, string>();

				string boundary;
				if (encapsulated)
				{
					boundary = null;
					for (int i = 0; i != encHeaders.Length; i++)
					{
						headers.put(encHeaders[i], encValues[i]);
					}
				}
				else
				{
					boundary = generateBoundary();

					// handle Content-Type specially
					StringBuffer contValue = new StringBuffer(detValues[0]);

					addHashHeader(contValue, sigGen.getDigestAlgorithms());

					addBoundary(contValue, boundary);
					headers.put(detHeaders[0], contValue.ToString());

					for (int i = 1; i < detHeaders.Length; i++)
					{
						headers.put(detHeaders[i], detValues[i]);
					}
				}

				for (Iterator it = extraHeaders.entrySet().iterator(); it.hasNext();)
				{
					Map.Entry ent = (Map.Entry)it.next();
					headers.put((string)ent.getKey(), (string)ent.getValue());
				}

				return new SMIMESignedWriter(this, headers, boundary, mimeOut);
			}

			public virtual void addHashHeader(StringBuffer header, List signers)
			{
				int count = 0;

				//
				// build the hash header
				//
				Iterator it = signers.iterator();
				Set micAlgSet = new TreeSet();

				while (it.hasNext())
				{
					AlgorithmIdentifier digest = (AlgorithmIdentifier)it.next();

					string micAlg = (string)micAlgs.get(digest.getAlgorithm());

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

			public virtual void addBoundary(StringBuffer header, string boundary)
			{
				 header.append(@";\r\n\tboundary=""");
				 header.append(boundary);
				 header.append(@"""");
			}

			public virtual string generateBoundary()
			{
				SecureRandom random = new SecureRandom();

				return "==" + (new BigInteger(180, random)).setBit(179).ToString(16) + "=";
			}
		}

		private readonly CMSSignedDataStreamGenerator sigGen;

		private readonly string boundary;
		private readonly OutputStream mimeOut;
		private readonly string contentTransferEncoding;

		private SMIMESignedWriter(Builder builder, Map<string, string> headers, string boundary, OutputStream mimeOut) : base(new Headers(mapToLines(headers), builder.contentTransferEncoding))
		{

			this.sigGen = builder.sigGen;
			this.contentTransferEncoding = builder.contentTransferEncoding;
			this.boundary = boundary;
			this.mimeOut = mimeOut;
		}

		/// <summary>
		/// Return a content stream for the signer - note data written to this stream needs to properly
		/// canonicalised if necessary.
		/// </summary>
		/// <returns> an output stream for data to be signed to be written to. </returns>
		/// <exception cref="IOException"> on a stream error. </exception>
		public override OutputStream getContentStream()
		{
			headers.dumpHeaders(mimeOut);

			mimeOut.write(Strings.toByteArray("\r\n"));

			if (string.ReferenceEquals(boundary, null))
			{
				return null; // TODO: new ContentOutputStream(sigGen.open(mimeOut, true), mimeOut);
			}
			else
			{
				mimeOut.write(Strings.toByteArray("This is an S/MIME signed message\r\n"));
				mimeOut.write(Strings.toByteArray("\r\n--"));
				mimeOut.write(Strings.toByteArray(boundary));
				mimeOut.write(Strings.toByteArray("\r\n"));

				ByteArrayOutputStream bOut = new ByteArrayOutputStream();

				Base64OutputStream stream = new Base64OutputStream(bOut);

				return new ContentOutputStream(this, sigGen.open(stream,false, SMimeUtils.createUnclosable(mimeOut)), mimeOut, bOut, stream);
			}
		}

		public class ContentOutputStream : OutputStream
		{
			private readonly SMIMESignedWriter outerInstance;

			internal readonly OutputStream main;
			internal readonly OutputStream backing;
			internal readonly ByteArrayOutputStream sigStream;
			internal readonly OutputStream sigBase;

			public ContentOutputStream(SMIMESignedWriter outerInstance, OutputStream main, OutputStream backing, ByteArrayOutputStream sigStream, OutputStream sigBase)
			{
				this.outerInstance = outerInstance;
				this.main = main;
				this.backing = backing;
				this.sigStream = sigStream;
				this.sigBase = sigBase;
			}

			public virtual void write(int i)
			{
				main.write(i);
			}

			public virtual void close()
			{
				if (!string.ReferenceEquals(outerInstance.boundary, null))
				{
					main.close();

					backing.write(Strings.toByteArray("\r\n--"));
					backing.write(Strings.toByteArray(outerInstance.boundary));
					backing.write(Strings.toByteArray("\r\n"));

					backing.write(Strings.toByteArray(@"Content-Type: application/pkcs7-signature; name=""smime.p7s""\r\n"));
					backing.write(Strings.toByteArray("Content-Transfer-Encoding: base64\r\n"));
					backing.write(Strings.toByteArray(@"Content-Disposition: attachment; filename=""smime.p7s""\r\n"));
					backing.write(Strings.toByteArray("\r\n"));

					if (sigBase != null)
					{
						sigBase.close();
					}

					backing.write(sigStream.toByteArray());

					backing.write(Strings.toByteArray("\r\n--"));
					backing.write(Strings.toByteArray(outerInstance.boundary));
					backing.write(Strings.toByteArray("--\r\n"));
				}

				if (backing != null)
				{
					backing.close();
				}
			}
		}
	}

}