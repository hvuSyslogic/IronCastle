namespace org.bouncycastle.pqc.jcajce.interfaces
{
	using QTESLAParameterSpec = org.bouncycastle.pqc.jcajce.spec.QTESLAParameterSpec;

	/// <summary>
	/// Base interface for a qTESLA key.
	/// </summary>
	public interface QTESLAKey
	{
		/// <summary>
		/// Return the parameters for this key - in this case the security category.
		/// </summary>
		/// <returns> a QTESLAParameterSpec </returns>
		QTESLAParameterSpec getParams();
	}

}