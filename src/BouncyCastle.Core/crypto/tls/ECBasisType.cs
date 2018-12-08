namespace org.bouncycastle.crypto.tls
{
	/// <summary>
	/// RFC 4492 5.4. (Errata ID: 2389)
	/// </summary>
	public class ECBasisType
	{
		public const short ec_basis_trinomial = 1;
		public const short ec_basis_pentanomial = 2;

		public static bool isValid(short ecBasisType)
		{
			return ecBasisType >= ec_basis_trinomial && ecBasisType <= ec_basis_pentanomial;
		}
	}

}