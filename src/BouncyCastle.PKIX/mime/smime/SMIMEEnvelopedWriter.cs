namespace org.bouncycastle.mime.smime
{

	using CMSAttributeTableGenerator = org.bouncycastle.cms.CMSAttributeTableGenerator;
	using CMSEnvelopedDataStreamGenerator = org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator;
	using CMSException = org.bouncycastle.cms.CMSException;
	using OriginatorInformation = org.bouncycastle.cms.OriginatorInformation;
	using RecipientInfoGenerator = org.bouncycastle.cms.RecipientInfoGenerator;
	using Base64OutputStream = org.bouncycastle.mime.encoding.Base64OutputStream;
	using OutputEncryptor = org.bouncycastle.@operator.OutputEncryptor;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Writer for SMIME Enveloped objects.
	/// </summary>
	public class SMIMEEnvelopedWriter : MimeWriter
	{
		public class Builder
		{
			internal static readonly string[] stdHeaders;
			internal static readonly string[] stdValues;

			static Builder()
			{
				stdHeaders = new string[] {"Content-Type", "Content-Disposition", "Content-Transfer-Encoding", "Content-Description"};

				stdValues = new string[] {@"application/pkcs7-mime; name=""smime.p7m""; smime-type=enveloped-data", @"attachment; filename=""smime.p7m""", "base64", "S/MIME Encrypted Message"};
			}

			internal readonly CMSEnvelopedDataStreamGenerator envGen = new CMSEnvelopedDataStreamGenerator();
			internal readonly Map<string, string> headers = new LinkedHashMap<string, string>();

			internal string contentTransferEncoding = "base64";

			public Builder()
			{
				for (int i = 0; i != stdHeaders.Length; i++)
				{
					headers.put(stdHeaders[i], stdValues[i]);
				}
			}

			public virtual Builder setUnprotectedAttributeGenerator(CMSAttributeTableGenerator unprotectedAttributeGenerator)
			{
				this.envGen.setUnprotectedAttributeGenerator(unprotectedAttributeGenerator);

				return this;
			}

			public virtual Builder setOriginatorInfo(OriginatorInformation originatorInfo)
			{
				this.envGen.setOriginatorInfo(originatorInfo);

				return this;
			}

			/// <summary>
			/// Specify a MIME header (name, value) pair for this builder. If the headerName already exists it will
			/// be overridden.
			/// </summary>
			/// <param name="headerName"> name of the MIME header. </param>
			/// <param name="headerValue"> value of the MIME header.
			/// </param>
			/// <returns> the current Builder instance. </returns>
			public virtual Builder withHeader(string headerName, string headerValue)
			{
				this.headers.put(headerName, headerValue);

				return this;
			}

			/// <summary>
			/// Add a generator to produce the recipient info required.
			/// </summary>
			/// <param name="recipientGenerator"> a generator of a recipient info object.
			/// </param>
			/// <returns> the current Builder instance. </returns>
			public virtual Builder addRecipientInfoGenerator(RecipientInfoGenerator recipientGenerator)
			{
				this.envGen.addRecipientInfoGenerator(recipientGenerator);

				return this;
			}

			public virtual SMIMEEnvelopedWriter build(OutputStream mimeOut, OutputEncryptor outEnc)
			{
				return new SMIMEEnvelopedWriter(this, outEnc, mimeOut);
			}
		}

		private readonly CMSEnvelopedDataStreamGenerator envGen;

		private readonly OutputEncryptor outEnc;
		private readonly OutputStream mimeOut;
		private readonly string contentTransferEncoding;

		private SMIMEEnvelopedWriter(Builder builder, OutputEncryptor outEnc, OutputStream mimeOut) : base(new Headers(mapToLines(builder.headers), builder.contentTransferEncoding))
		{

			this.envGen = builder.envGen;
			this.contentTransferEncoding = builder.contentTransferEncoding;
			this.outEnc = outEnc;
			this.mimeOut = mimeOut;
		}

		public override OutputStream getContentStream()
		{
			headers.dumpHeaders(mimeOut);

			mimeOut.write(Strings.toByteArray("\r\n"));

			try
			{
				OutputStream outStream;

				if ("base64".Equals(contentTransferEncoding))
				{
					outStream = new Base64OutputStream(mimeOut);

					return new ContentOutputStream(this, envGen.open(SMimeUtils.createUnclosable(outStream), outEnc), outStream);
				}
				else
				{
					return new ContentOutputStream(this, envGen.open(SMimeUtils.createUnclosable(mimeOut), outEnc), null);
				}
			}
			catch (CMSException e)
			{
				throw new MimeIOException(e.Message, e);
			}
		}

		public class ContentOutputStream : OutputStream
		{
			private readonly SMIMEEnvelopedWriter outerInstance;

			internal readonly OutputStream main;
			internal readonly OutputStream backing;

			public ContentOutputStream(SMIMEEnvelopedWriter outerInstance, OutputStream main, OutputStream backing)
			{
				this.outerInstance = outerInstance;
				this.main = main;
				this.backing = backing;
			}

			public virtual void write(int i)
			{
				main.write(i);
			}

			public virtual void close()
			{
				main.close();
				if (backing != null)
				{
					backing.close();
				}
			}
		}
	}

}