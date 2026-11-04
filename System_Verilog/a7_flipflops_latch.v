`define DELAY #2 //Flip-flop delay

// 1. Rising edge, simple
module dff_pos (d, clk, q);
    input d, clk; output q; reg q;
    always @ (posedge clk) q <= `DELAY d;
endmodule

// 2. Rising edge, synchronous reset (active high)
module dff_pos_sync (d, clk, reset, q);
    input d, clk, reset; output q; reg q;
    always @ (posedge clk)
        if (reset) q <= 0; else q <= `DELAY d;
endmodule

// 3. Rising edge, asynchronous reset, active high
module dff_pos_async_hi (d, clk, reset, q);
    input d, clk, reset; output q; reg q;
    always @ (posedge clk or posedge reset)
        if (reset) q <= 0; else q <= `DELAY d;
endmodule

// 4. Rising edge, asynchronous reset, active low
module dff_pos_async_lo (d, clk, reset_n, q);
    input d, clk, reset_n; output q; reg q;
    always @ (posedge clk or negedge reset_n)
        if (!reset_n) q <= 0; else q <= `DELAY d;
endmodule

// 5. Falling edge, simple
module dff_neg (d, clk, q);
    input d, clk; output q; reg q;
    always @ (negedge clk) q <= `DELAY d;
endmodule

// 6. Falling edge, synchronous reset (active high)
module dff_neg_sync (d, clk, reset, q);
    input d, clk, reset; output q; reg q;
    always @ (negedge clk)
        if (reset) q <= 0; else q <= `DELAY d;
endmodule

// 7. Falling edge, asynchronous reset, active high
module dff_neg_async_hi (d, clk, reset, q);
    input d, clk, reset; output q; reg q;
    always @ (negedge clk or posedge reset)
        if (reset) q <= 0; else q <= `DELAY d;
endmodule

// 8. Falling edge, asynchronous reset, active low
module dff_neg_async_lo (d, clk, reset_n, q);
    input d, clk, reset_n; output q; reg q;
    always @ (negedge clk or negedge reset_n)
        if (!reset_n) q <= 0; else q <= `DELAY d;
endmodule

// 9. Latch (transparent when en = 1)
module latch (d, en, q);
    input d, en; output q; reg q;
    always @ (d or en)
        if (en) q = d;
endmodule

module main();
    reg d, clk, reset, en;
    wire reset_n = ~reset;
    wire q1, q2, q3, q4, q5, q6, q7, q8, q9;

    dff_pos           u1(d, clk, q1);
    dff_pos_sync      u2(d, clk, reset, q2);
    dff_pos_async_hi  u3(d, clk, reset, q3);
    dff_pos_async_lo  u4(d, clk, reset_n, q4);
    dff_neg           u5(d, clk, q5);
    dff_neg_sync      u6(d, clk, reset, q6);
    dff_neg_async_hi  u7(d, clk, reset, q7);
    dff_neg_async_lo  u8(d, clk, reset_n, q8);
    latch             u9(d, en, q9);

    always #10 clk = ~clk;          // clock period = 20

    initial
    begin
        $display("time clk d rst en | pos pos_s pos_ah pos_al | neg neg_s neg_ah neg_al | latch");
        $monitor("%4t  %b  %b  %b   %b  |  %b    %b     %b      %b   |  %b    %b     %b      %b   |  %b",
                 $time, clk, d, reset, en, q1, q2, q3, q4, q5, q6, q7, q8, q9);
        clk = 0; d = 0; reset = 1; en = 0;
        #25 reset = 0;
        #10 d = 1; en = 1;        // d high, latch transparent
        #30 en = 0;
        #5  d = 0;                // latch holds, flops wait for edge
        #30 d = 1;
        #17 reset = 1;            // async resets act immediately, sync ones at next edge
        #25 reset = 0; en = 1;
        #20 d = 0;
        #40 $finish;
    end
endmodule

//Developed with assistance from Claude (AI assistant by Anthropic)