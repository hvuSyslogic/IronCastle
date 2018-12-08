using BouncyCastle.Core.Port;

namespace org.bouncycastle.math.field
{

	public interface FiniteField
	{
		BigInteger getCharacteristic();

		int getDimension();
	}

}