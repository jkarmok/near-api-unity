using System.Numerics;

namespace NearClientUnity.Utilities
{
    public static class UnitConverter
    {
        public static UInt128 GetYoctoNearFormat(double amount)
        {
            UInt128 uint128_1 = new UInt128(amount * 1000000000.0);
            UInt128 c;
            UInt128.Create(out c, 1000000000000000L);
            UInt128 uint128_2 = c;
            return uint128_1 * uint128_2;
        }

        public static double? GetNearFormat(UInt128? amount)
        {
            if (!amount.HasValue)
                return new double?();
            UInt128 uint128 = new UInt128((BigInteger)(amount.Value / 1000000000UL));
            double? nullable1 = new double?(1E+15);
            double num = (double)uint128;
            double? nullable2 = nullable1;
            return !nullable2.HasValue ? new double?() : new double?(num / nullable2.GetValueOrDefault());
        }

        public static ulong? GetGasFormat(double? amount)
        {
            if (!amount.HasValue)
                return new ulong?();
            double? nullable1 = amount;
            ulong? nullable2 = nullable1.HasValue ? new ulong?((ulong)nullable1.GetValueOrDefault()) : new ulong?();
            ulong num = 1000000000000;
            return !nullable2.HasValue ? new ulong?() : new ulong?(nullable2.GetValueOrDefault() * num);
        }

        public static double? GetTGasFormat(ulong? amount)
        {
            if (!amount.HasValue)
                return new double?();
            ulong? nullable1 = amount;
            double? nullable2 = nullable1.HasValue ? new double?((double)nullable1.GetValueOrDefault()) : new double?();
            double num = 1000000000000.0;
            return !nullable2.HasValue ? new double?() : new double?(nullable2.GetValueOrDefault() / num);
        }
    }
}
