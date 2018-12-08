namespace org.bouncycastle.dvcs
{
	using Data = org.bouncycastle.asn1.dvcs.Data;
	using CMSException = org.bouncycastle.cms.CMSException;
	using CMSSignedData = org.bouncycastle.cms.CMSSignedData;

	/// <summary>
	/// Data piece of DVCS request to VSD service (Verify Signed Document).
	/// It contains VSD-specific selector interface.
	/// Note: the request should contain CMS SignedData object as message.
	/// <para>
	/// This objects are constructed internally,
	/// to build DVCS request to VSD service use VSDRequestBuilder.
	/// </para>
	/// </summary>
	public class VSDRequestData : DVCSRequestData
	{
		private CMSSignedData doc;

		public VSDRequestData(Data data) : base(data)
		{
			initDocument();
		}

		private void initDocument()
		{
			if (doc == null)
			{
				if (data.getMessage() == null)
				{
					throw new DVCSConstructionException("DVCSRequest.data.message should be specified for VSD service");
				}
				try
				{
					doc = new CMSSignedData(data.getMessage().getOctets());
				}
				catch (CMSException e)
				{
					throw new DVCSConstructionException("Can't read CMS SignedData from input", e);
				}
			}
		}

		/// <summary>
		/// Get contained message (data to be certified).
		/// </summary>
		/// <returns> the contained message. </returns>
		public virtual byte[] getMessage()
		{
			return data.getMessage().getOctets();
		}

		/// <summary>
		/// Get the CMS SignedData object represented by the encoded message.
		/// </summary>
		/// <returns> the parsed contents of the contained message as a CMS SignedData object. </returns>
		public virtual CMSSignedData getParsedMessage()
		{
			return doc;
		}
	}

}