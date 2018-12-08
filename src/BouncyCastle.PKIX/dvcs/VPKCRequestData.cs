namespace org.bouncycastle.dvcs
{

	using Data = org.bouncycastle.asn1.dvcs.Data;
	using TargetEtcChain = org.bouncycastle.asn1.dvcs.TargetEtcChain;

	/// <summary>
	/// Data piece of DVCS request to VPKC service (Verify Public Key Certificates).
	/// It contains VPKC-specific interface.
	/// <para>
	/// This objects are constructed internally,
	/// to build DVCS request to VPKC service use VPKCRequestBuilder.
	/// </para>
	/// </summary>
	public class VPKCRequestData : DVCSRequestData
	{
		private List chains;

		public VPKCRequestData(Data data) : base(data)
		{

			TargetEtcChain[] certs = data.getCerts();

			if (certs == null)
			{
				throw new DVCSConstructionException("DVCSRequest.data.certs should be specified for VPKC service");
			}

			chains = new ArrayList(certs.Length);

			for (int i = 0; i != certs.Length; i++)
			{
				chains.add(new TargetChain(certs[i]));
			}
		}

		/// <summary>
		/// Get contained certs choice data..
		/// </summary>
		/// <returns> a list of CertChain objects. </returns>
		public virtual List getCerts()
		{
			return Collections.unmodifiableList(chains);
		}
	}

}