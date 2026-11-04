// 4-bit Gray to Binary converter using XOR gates
// b3 = g3 ; b2 = b3^g2 ; b1 = b2^g1 ; b0 = b1^g0
module GraytoBin1(g, b);
    input  [3:0] g;   // g[3] = MSB ... g[0] = LSB
    output [3:0] b;
    assign b[3] = g[3];
    xor (b[2], b[3], g[2]);
    xor (b[1], b[2], g[1]);
    xor (b[0], b[1], g[0]);
endmodule

module main();
    reg  [3:0] g;
    wire [3:0] b;
    integer i;

    GraytoBin1 u1(g, b);

    initial
    begin
        $monitor("Gray = %b  ->  Binary = %b", g, b);
        for (i = 0; i < 16; i = i + 1)
        begin
            g = i;
            #5;
        end
    end
endmodule

//Developed with assistance from Claude (AI assistant by Anthropic)
