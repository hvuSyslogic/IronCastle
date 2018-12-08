namespace org.bouncycastle.math.ec.endo
{

	public interface ECEndomorphism
	{
		ECPointMap getPointMap();

		bool hasEfficientPointMap();
	}

}