using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.pqc.crypto.qtesla
{
	/// <summary>
	/// The qTESLA security categories.
	/// </summary>
	public class QTESLASecurityCategory
	{
		public const int HEURISTIC_I = 0;
		public const int HEURISTIC_III_SIZE = 1;
		public const int HEURISTIC_III_SPEED = 2;
		public const int PROVABLY_SECURE_I = 3;
		public const int PROVABLY_SECURE_III = 4;

		private QTESLASecurityCategory()
		{
		}

		internal static void validate(int securityCategory)
		{
			switch (securityCategory)
			{
			case HEURISTIC_I:
			case HEURISTIC_III_SIZE:
			case HEURISTIC_III_SPEED:
			case PROVABLY_SECURE_I:
			case PROVABLY_SECURE_III:
				break;
			default:
				throw new IllegalArgumentException("unknown security category: " + securityCategory);
			}
		}

		internal static int getPrivateSize(int securityCategory)
		{
			switch (securityCategory)
			{
			case HEURISTIC_I:
				return Polynomial.PRIVATE_KEY_I;
			case HEURISTIC_III_SIZE:
				return Polynomial.PRIVATE_KEY_III_SIZE;
			case HEURISTIC_III_SPEED:
				return Polynomial.PRIVATE_KEY_III_SPEED;
			case PROVABLY_SECURE_I:
				return Polynomial.PRIVATE_KEY_I_P;
			case PROVABLY_SECURE_III:
				return Polynomial.PRIVATE_KEY_III_P;
			default:
				throw new IllegalArgumentException("unknown security category: " + securityCategory);
			}
		}

		internal static int getPublicSize(int securityCategory)
		{
			switch (securityCategory)
			{
			case HEURISTIC_I:
				return Polynomial.PUBLIC_KEY_I;
			case HEURISTIC_III_SIZE:
				return Polynomial.PUBLIC_KEY_III_SIZE;
			case HEURISTIC_III_SPEED:
				return Polynomial.PUBLIC_KEY_III_SPEED;
			case PROVABLY_SECURE_I:
				return Polynomial.PUBLIC_KEY_I_P;
			case PROVABLY_SECURE_III:
				return Polynomial.PUBLIC_KEY_III_P;
			default:
				throw new IllegalArgumentException("unknown security category: " + securityCategory);
			}
		}

		internal static int getSignatureSize(int securityCategory)
		{
			switch (securityCategory)
			{
			case HEURISTIC_I:
				return Polynomial.SIGNATURE_I;
			case HEURISTIC_III_SIZE:
				return Polynomial.SIGNATURE_III_SIZE;
			case HEURISTIC_III_SPEED:
				return Polynomial.SIGNATURE_III_SPEED;
			case PROVABLY_SECURE_I:
				return Polynomial.SIGNATURE_I_P;
			case PROVABLY_SECURE_III:
				return Polynomial.SIGNATURE_III_P;
			default:
				throw new IllegalArgumentException("unknown security category: " + securityCategory);
			}
		}

		/// <summary>
		/// Return a standard name for the security category.
		/// </summary>
		/// <param name="securityCategory"> the category of interest. </param>
		/// <returns> the name for the category. </returns>
		public static string getName(int securityCategory)
		{
			switch (securityCategory)
			{
			case HEURISTIC_I:
				return "qTESLA-I";
			case HEURISTIC_III_SIZE:
				return "qTESLA-III-size";
			case HEURISTIC_III_SPEED:
				return "qTESLA-III-speed";
			case PROVABLY_SECURE_I:
				return "qTESLA-p-I";
			case PROVABLY_SECURE_III:
				return "qTESLA-p-III";
			default:
				throw new IllegalArgumentException("unknown security category: " + securityCategory);
			}
		}
	}

}