namespace org.bouncycastle.math.field
{
	public interface ExtensionField : FiniteField
	{
		FiniteField getSubfield();

		int getDegree();
	}

}