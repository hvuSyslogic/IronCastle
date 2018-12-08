namespace org.bouncycastle.dvcs
{
	using Data = org.bouncycastle.asn1.dvcs.Data;

	/// <summary>
	/// Data piece of DVCRequest object (DVCS Data structure).
	/// Its contents depend on the service type.
	/// Its subclasses define the service-specific interface.
	/// <para>
	/// The concrete objects of DVCRequestData are created by buildDVCRequestData static method.
	/// </para>
	/// </summary>
	public abstract class DVCSRequestData
	{
		/// <summary>
		/// The underlying data object is accessible by subclasses.
		/// </summary>
		protected internal Data data;

		/// <summary>
		/// The constructor is accessible by subclasses.
		/// </summary>
		/// <param name="data"> the data piece for this request. </param>
		public DVCSRequestData(Data data)
		{
			this.data = data;
		}

		/// <summary>
		/// Convert to ASN.1 structure (Data).
		/// </summary>
		/// <returns> a Data object. </returns>
		public virtual Data toASN1Structure()
		{
			return data;
		}
	}

}