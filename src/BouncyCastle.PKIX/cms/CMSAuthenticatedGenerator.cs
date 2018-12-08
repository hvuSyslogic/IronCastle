namespace org.bouncycastle.cms
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using Arrays = org.bouncycastle.util.Arrays;

	public class CMSAuthenticatedGenerator : CMSEnvelopedGenerator
	{
		protected internal CMSAttributeTableGenerator authGen;
		protected internal CMSAttributeTableGenerator unauthGen;

		/// <summary>
		/// base constructor
		/// </summary>
		public CMSAuthenticatedGenerator()
		{
		}

		public virtual void setAuthenticatedAttributeGenerator(CMSAttributeTableGenerator authGen)
		{
			this.authGen = authGen;
		}

		public virtual void setUnauthenticatedAttributeGenerator(CMSAttributeTableGenerator unauthGen)
		{
			this.unauthGen = unauthGen;
		}

		public virtual Map getBaseParameters(ASN1ObjectIdentifier contentType, AlgorithmIdentifier digAlgId, AlgorithmIdentifier macAlgId, byte[] hash)
		{
			Map param = new HashMap();
			param.put(CMSAttributeTableGenerator_Fields.CONTENT_TYPE, contentType);
			param.put(CMSAttributeTableGenerator_Fields.DIGEST_ALGORITHM_IDENTIFIER, digAlgId);
			param.put(CMSAttributeTableGenerator_Fields.DIGEST, Arrays.clone(hash));
			param.put(CMSAttributeTableGenerator_Fields.MAC_ALGORITHM_IDENTIFIER, macAlgId);
			return param;
		}
	}

}