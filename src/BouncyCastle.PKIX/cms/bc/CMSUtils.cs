namespace org.bouncycastle.cms.bc
{
	using CipherParameters = org.bouncycastle.crypto.CipherParameters;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using GenericKey = org.bouncycastle.@operator.GenericKey;

	public class CMSUtils
	{
		internal static CipherParameters getBcKey(GenericKey key)
		{
			if (key.getRepresentation() is CipherParameters)
			{
				return (CipherParameters)key.getRepresentation();
			}

			if (key.getRepresentation() is byte[])
			{
				return new KeyParameter((byte[])key.getRepresentation());
			}

			throw new IllegalArgumentException("unknown generic key type");
		}
	}

}