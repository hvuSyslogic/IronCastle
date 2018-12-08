namespace org.bouncycastle.@operator.bc
{

	public class OperatorUtils
	{
		internal static byte[] getKeyBytes(GenericKey key)
		{
			if (key.getRepresentation() is Key)
			{
				return ((Key)key.getRepresentation()).getEncoded();
			}

			if (key.getRepresentation() is byte[])
			{
				return (byte[])key.getRepresentation();
			}

			throw new IllegalArgumentException("unknown generic key type");
		}
	}
}