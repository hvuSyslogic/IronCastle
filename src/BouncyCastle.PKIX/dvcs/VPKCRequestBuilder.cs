using System;

namespace org.bouncycastle.dvcs
{

	using CertEtcToken = org.bouncycastle.asn1.dvcs.CertEtcToken;
	using DVCSRequestInformationBuilder = org.bouncycastle.asn1.dvcs.DVCSRequestInformationBuilder;
	using DVCSTime = org.bouncycastle.asn1.dvcs.DVCSTime;
	using Data = org.bouncycastle.asn1.dvcs.Data;
	using ServiceType = org.bouncycastle.asn1.dvcs.ServiceType;
	using TargetEtcChain = org.bouncycastle.asn1.dvcs.TargetEtcChain;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using X509CertificateHolder = org.bouncycastle.cert.X509CertificateHolder;

	/// <summary>
	/// Builder of DVC requests to VPKC service (Verify Public Key Certificates).
	/// </summary>
	public class VPKCRequestBuilder : DVCSRequestBuilder
	{
		private List chains = new ArrayList();

		public VPKCRequestBuilder() : base(new DVCSRequestInformationBuilder(ServiceType.VPKC))
		{
		}

		/// <summary>
		/// Adds a TargetChain representing a X.509 certificate to the request.
		/// </summary>
		/// <param name="cert"> the certificate to be added </param>
		public virtual void addTargetChain(X509CertificateHolder cert)
		{
			chains.add(new TargetEtcChain(new CertEtcToken(CertEtcToken.TAG_CERTIFICATE, cert.toASN1Structure())));
		}

		/// <summary>
		/// Adds a TargetChain representing a single X.509 Extension to the request
		/// </summary>
		/// <param name="extension"> the extension to be added. </param>
		public virtual void addTargetChain(Extension extension)
		{
			chains.add(new TargetEtcChain(new CertEtcToken(extension)));
		}

		/// <summary>
		/// Adds a X.509 certificate to the request.
		/// </summary>
		/// <param name="targetChain"> the CertChain object to be added. </param>
		public virtual void addTargetChain(TargetChain targetChain)
		{
			chains.add(targetChain.toASN1Structure());
		}

		public virtual void setRequestTime(DateTime requestTime)
		{
			requestInformationBuilder.setRequestTime(new DVCSTime(requestTime));
		}

		/// <summary>
		/// Build DVCS request to VPKC service.
		/// </summary>
		/// <returns> a new DVCSRequest based on the state of this builder. </returns>
		/// <exception cref="DVCSException"> if an issue occurs during construction. </exception>
		public virtual DVCSRequest build()
		{
			Data data = new Data((TargetEtcChain[])chains.toArray(new TargetEtcChain[chains.size()]));

			return createDVCRequest(data);
		}
	}

}