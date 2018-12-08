namespace org.bouncycastle.pqc.jcajce.spec
{

	using QTESLASecurityCategory = org.bouncycastle.pqc.crypto.qtesla.QTESLASecurityCategory;

	/// <summary>
	/// qTESLA parameter details. These are divided up on the basis of the security categories for each
	/// individual parameter set.
	/// </summary>
	public class QTESLAParameterSpec : AlgorithmParameterSpec
	{
		/// <summary>
		/// Available security categories.
		/// </summary>
		public static readonly string HEURISTIC_I = QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_I);
		public static readonly string HEURISTIC_III_SIZE = QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_III_SIZE);
		public static readonly string HEURISTIC_III_SPEED = QTESLASecurityCategory.getName(QTESLASecurityCategory.HEURISTIC_III_SPEED);
		public static readonly string PROVABLY_SECURE_I = QTESLASecurityCategory.getName(QTESLASecurityCategory.PROVABLY_SECURE_I);
		public static readonly string PROVABLY_SECURE_III = QTESLASecurityCategory.getName(QTESLASecurityCategory.PROVABLY_SECURE_III);

		private string securityCategory;

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="securityCategory"> the security category we want this parameterSpec to match. </param>
		public QTESLAParameterSpec(string securityCategory)
		{
			this.securityCategory = securityCategory;
		}

		/// <summary>
		/// Return the security category.
		/// </summary>
		/// <returns> the security category. </returns>
		public virtual string getSecurityCategory()
		{
			return securityCategory;
		}
	}

}