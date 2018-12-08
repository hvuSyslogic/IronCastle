namespace org.bouncycastle.math.field
{
	public interface PolynomialExtensionField : ExtensionField
	{
		Polynomial getMinimalPolynomial();
	}

}