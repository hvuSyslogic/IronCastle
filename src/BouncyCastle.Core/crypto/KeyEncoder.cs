namespace org.bouncycastle.crypto
{
	using AsymmetricKeyParameter = org.bouncycastle.crypto.@params.AsymmetricKeyParameter;

	public interface KeyEncoder
	{
		byte[] getEncoded(AsymmetricKeyParameter keyParameter);
	}

}