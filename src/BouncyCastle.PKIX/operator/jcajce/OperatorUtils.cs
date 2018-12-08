namespace org.bouncycastle.@operator.jcajce
{


	public class OperatorUtils
	{
		internal static Key getJceKey(GenericKey key)
		{
			if (key.getRepresentation() is Key)
			{
				return (Key)key.getRepresentation();
			}

			if (key.getRepresentation() is byte[])
			{
				return new SecretKeySpec((byte[])key.getRepresentation(), "ENC");
			}

			throw new IllegalArgumentException("unknown generic key type");
		}
	}
}