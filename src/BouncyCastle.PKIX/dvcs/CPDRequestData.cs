namespace org.bouncycastle.dvcs
{
	using Data = org.bouncycastle.asn1.dvcs.Data;

	/// <summary>
	/// Data piece of DVCRequest for CPD service (Certify Possession of Data).
	/// It contains CPD-specific selector interface.
	/// <para>
	/// This objects are constructed internally,
	/// to build DVCS request to CPD service use CPDRequestBuilder.
	/// </para>
	/// </summary>
	public class CPDRequestData : DVCSRequestData
	{
		public CPDRequestData(Data data) : base(data)
		{
			initMessage();
		}

		private void initMessage()
		{
			if (data.getMessage() == null)
			{
				throw new DVCSConstructionException("DVCSRequest.data.message should be specified for CPD service");
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
	}

}