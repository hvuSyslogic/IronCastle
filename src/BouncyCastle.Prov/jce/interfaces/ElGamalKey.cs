namespace org.bouncycastle.jce.interfaces
{

	using ElGamalParameterSpec = org.bouncycastle.jce.spec.ElGamalParameterSpec;

	public interface ElGamalKey : DHKey
	{
		ElGamalParameterSpec getParameters();
	}

}