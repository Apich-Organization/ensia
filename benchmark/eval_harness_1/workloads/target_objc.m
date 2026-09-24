__attribute__((objc_root_class))
@interface SecureVault
- (int)validatePin:(int)pin;
@end

@implementation SecureVault
- (int)validatePin:(int)pin {
    return pin == 1337;
}
@end
