namespace org.bouncycastle.@operator.bc
{
	using AESWrapEngine = org.bouncycastle.crypto.engines.AESWrapEngine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;

	public class BcAESSymmetricKeyUnwrapper : BcSymmetricKeyUnwrapper
	{
		public BcAESSymmetricKeyUnwrapper(KeyParameter wrappingKey) : base(AESUtil.determineKeyEncAlg(wrappingKey), new AESWrapEngine(), wrappingKey)
		{
		}
	}

}