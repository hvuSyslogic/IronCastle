namespace org.bouncycastle.mime.smime
{

	using DigestCalculatorProvider = org.bouncycastle.@operator.DigestCalculatorProvider;

	public class SMimeParserProvider : MimeParserProvider
	{
		private readonly string defaultContentTransferEncoding;
		private readonly DigestCalculatorProvider digestCalculatorProvider;

		public SMimeParserProvider(string defaultContentTransferEncoding, DigestCalculatorProvider digestCalculatorProvider)
		{
			this.defaultContentTransferEncoding = defaultContentTransferEncoding;
			this.digestCalculatorProvider = digestCalculatorProvider;
		}

		public virtual MimeParser createParser(InputStream source)
		{
			return new BasicMimeParser(new SMimeParserContext(defaultContentTransferEncoding, digestCalculatorProvider), source);
		}

		public virtual MimeParser createParser(Headers headers, InputStream source)
		{
			return new BasicMimeParser(new SMimeParserContext(defaultContentTransferEncoding, digestCalculatorProvider), headers, source);
		}
	}

}