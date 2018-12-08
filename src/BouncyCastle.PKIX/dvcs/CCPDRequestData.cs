namespace org.bouncycastle.dvcs
{
	using Data = org.bouncycastle.asn1.dvcs.Data;

	/// <summary>
	/// Data piece of DVCRequest for CCPD service (Certify Claim of Possession of Data).
	/// It contains CCPD-specific selector interface.
	/// <para>
	/// This objects are constructed internally,
	/// to build DVCS request to CCPD service use CCPDRequestBuilder.
	/// </para>
	/// </summary>
	public class CCPDRequestData : DVCSRequestData
	{
		/// <summary>
		/// Construct from corresponding ASN.1 Data structure.
		/// Note, that data should have messageImprint choice,
		/// otherwise DVCSConstructionException is thrown.
		/// </summary>
		/// <param name="data"> </param>
		/// <exception cref="DVCSConstructionException"> </exception>
		public CCPDRequestData(Data data) : base(data)
		{
			initDigest();
		}

		private void initDigest()
		{
			if (data.getMessageImprint() == null)
			{
				throw new DVCSConstructionException("DVCSRequest.data.messageImprint should be specified for CCPD service");
			}
		}

		/// <summary>
		/// Get MessageImprint value
		/// </summary>
		/// <returns> the message imprint data as a MessageImprint object. </returns>
		public virtual MessageImprint getMessageImprint()
		{
			return new MessageImprint(data.getMessageImprint());
		}
	}

}