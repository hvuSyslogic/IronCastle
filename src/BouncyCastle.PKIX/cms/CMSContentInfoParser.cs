namespace org.bouncycastle.cms
{

	using ASN1SequenceParser = org.bouncycastle.asn1.ASN1SequenceParser;
	using ASN1StreamParser = org.bouncycastle.asn1.ASN1StreamParser;
	using ContentInfoParser = org.bouncycastle.asn1.cms.ContentInfoParser;

	public class CMSContentInfoParser
	{
		protected internal ContentInfoParser _contentInfo;
		protected internal InputStream _data;

		public CMSContentInfoParser(InputStream data)
		{
			_data = data;

			try
			{
				ASN1StreamParser @in = new ASN1StreamParser(data);
				ASN1SequenceParser seqParser = (ASN1SequenceParser)@in.readObject();

				if (seqParser == null)
				{
					throw new CMSException("No content found.");
				}

				_contentInfo = new ContentInfoParser(seqParser);
			}
			catch (IOException e)
			{
				throw new CMSException("IOException reading content.", e);
			}
			catch (ClassCastException e)
			{
				throw new CMSException("Unexpected object reading content.", e);
			}
		}

		/// <summary>
		/// Close the underlying data stream. </summary>
		/// <exception cref="IOException"> if the close fails. </exception>
		public virtual void close()
		{
			_data.close();
		}
	}

}