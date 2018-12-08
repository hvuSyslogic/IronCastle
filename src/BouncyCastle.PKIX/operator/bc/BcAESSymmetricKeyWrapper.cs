namespace org.bouncycastle.@operator.bc
{
	using AESWrapEngine = org.bouncycastle.crypto.engines.AESWrapEngine;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;

	public class BcAESSymmetricKeyWrapper : BcSymmetricKeyWrapper
	{
		public BcAESSymmetricKeyWrapper(KeyParameter wrappingKey) : base(AESUtil.determineKeyEncAlg(wrappingKey), new AESWrapEngine(), wrappingKey)
		{
		}
	}

}