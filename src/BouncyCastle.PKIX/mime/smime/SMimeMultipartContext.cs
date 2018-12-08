namespace org.bouncycastle.mime.smime
{

	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using OperatorCreationException = org.bouncycastle.@operator.OperatorCreationException;
	using TeeInputStream = org.bouncycastle.util.io.TeeInputStream;
	using TeeOutputStream = org.bouncycastle.util.io.TeeOutputStream;

	public class SMimeMultipartContext : MimeMultipartContext
	{
		private readonly SMimeParserContext parserContext;

		private DigestCalculator[] calculators;


		public SMimeMultipartContext(MimeParserContext parserContext, Headers headers)
		{
			this.parserContext = (SMimeParserContext)parserContext;
			this.calculators = createDigestCalculators(headers);
		}

		public virtual DigestCalculator[] getDigestCalculators()
		{
			return calculators;
		}

		public virtual OutputStream getDigestOutputStream()
		{
			if (calculators.Length == 1)
			{
				return calculators[0].getOutputStream();
			}
			else
			{
				OutputStream compoundStream = calculators[0].getOutputStream();

				for (int i = 1; i < calculators.Length; i++)
				{
					compoundStream = new TeeOutputStream(calculators[i].getOutputStream(), compoundStream);
				}

				return compoundStream;
			}
		}

		private DigestCalculator[] createDigestCalculators(Headers headers)
		{
			try
			{
				Map<string, string> contentTypeFields = headers.getContentTypeAttributes();

				string micalgs = (string)contentTypeFields.get("micalg");
				if (string.ReferenceEquals(micalgs, null))
				{
					throw new IllegalStateException("No micalg field on content-type header");
				}

				string[] algs = micalgs.Substring(micalgs.IndexOf('=') + 1).Split(",", true);
				DigestCalculator[] dcOut = new DigestCalculator[algs.Length];

				for (int t = 0; t < algs.Length; t++)
				{
					// Deal with possibility of quoted parts, eg  "SHA1","SHA256" etc
					string alg = SMimeUtils.lessQuotes(algs[t]).Trim();
					dcOut[t] = parserContext.getDigestCalculatorProvider().get(new AlgorithmIdentifier(SMimeUtils.getDigestOID(alg)));
				}

				return dcOut;
			}
			catch (OperatorCreationException)
			{
				return null;
			}
		}

//JAVA TO C# CONVERTER WARNING: 'final' parameters are not available in .NET:
//ORIGINAL LINE: public org.bouncycastle.mime.MimeContext createContext(final int partNo) throws java.io.IOException
		public virtual MimeContext createContext(int partNo)
		{
			return new MimeContextAnonymousInnerClass(this, partNo);
		}

		public class MimeContextAnonymousInnerClass : MimeContext
		{
			private readonly SMimeMultipartContext outerInstance;

			private int partNo;

			public MimeContextAnonymousInnerClass(SMimeMultipartContext outerInstance, int partNo)
			{
				this.outerInstance = outerInstance;
				this.partNo = partNo;
			}

			public InputStream applyContext(Headers headers, InputStream contentStream)
			{
				if (partNo == 0)
				{
					OutputStream digestOut = outerInstance.getDigestOutputStream();

					headers.dumpHeaders(digestOut);

					digestOut.write('\r');
					digestOut.write('\n');

					return new TeeInputStream(contentStream, new CanonicalOutputStream(outerInstance.parserContext, headers, digestOut));
				}

				return contentStream;
			}
		}

		public virtual InputStream applyContext(Headers headers, InputStream contentStream)
		{
			return contentStream;
		}
	}

}