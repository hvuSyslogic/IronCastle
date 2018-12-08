namespace org.bouncycastle.cms.bc
{
	using KEKIdentifier = org.bouncycastle.asn1.cms.KEKIdentifier;
	using BcSymmetricKeyWrapper = org.bouncycastle.@operator.bc.BcSymmetricKeyWrapper;

	public class BcKEKRecipientInfoGenerator : KEKRecipientInfoGenerator
	{
		public BcKEKRecipientInfoGenerator(KEKIdentifier kekIdentifier, BcSymmetricKeyWrapper kekWrapper) : base(kekIdentifier, kekWrapper)
		{
		}

		public BcKEKRecipientInfoGenerator(byte[] keyIdentifier, BcSymmetricKeyWrapper kekWrapper) : this(new KEKIdentifier(keyIdentifier, null, null), kekWrapper)
		{
		}
	}

}