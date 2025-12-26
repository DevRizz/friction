clc; clear; close all;

%% ================= USER INPUT =================
filename = 'landing_data.xlsx';
numSheets = 9;
g = 9.81;                 % gravity
mass = 65000;             % aircraft mass [kg] (EDIT if known)

%% ================= LOOP OVER LANDINGS =================
for s = 1:numSheets

    %% ---------- LOAD DATA ----------
    T = readtable(filename, 'Sheet', s);

    time = T.Time;                        % seconds
    lat  = T.Lat;
    lon  = T.Lon;
    Vg   = T.GroundSpeed;                 % m/s
    mu   = T.Mu;
    FL   = T.FrictionLimited;             % 1 = friction limited
    BL   = T.BrakeL;
    BR   = T.BrakeR;
    RevL = T.RevL;
    RevR = T.RevR;

    dt = mean(diff(time));

    %% ---------- DERIVED PARAMETERS ----------
    % Deceleration
    ax = gradient(Vg, dt);                % m/s^2 (negative = decel)

    % Distance traveled
    dist = cumtrapz(time, Vg);

    % Average braking & reverser
    BrakeAvg = (BL + BR)/2;
    RevAvg   = (RevL + RevR)/2;

    % Asymmetries
    BrakeDiff = BL - BR;
    RevDiff   = RevL - RevR;

    %% ================= PLOTS =================

    figure('Name', ['Landing ', num2str(s)], 'Position', [100 100 1200 900])

    % --- Speed vs Time ---
    subplot(3,3,1)
    plot(time, Vg, 'LineWidth', 1.5)
    xlabel('Time (s)'), ylabel('Ground Speed (m/s)')
    title('Ground Speed vs Time'), grid on

    % --- Deceleration vs Time ---
    subplot(3,3,2)
    plot(time, ax, 'LineWidth', 1.5), hold on
    plot(time(FL==1), ax(FL==1), 'ro')
    xlabel('Time (s)'), ylabel('Longitudinal Accel (m/s^2)')
    title('Deceleration (Red = Friction Limited)')
    grid on

    % --- Distance vs Time ---
    subplot(3,3,3)
    plot(time, dist, 'LineWidth', 1.5)
    xlabel('Time (s)'), ylabel('Distance (m)')
    title('Ground Roll Distance'), grid on

    % --- Brake Pressure vs Deceleration ---
    subplot(3,3,4)
    scatter(BrakeAvg, abs(ax), 30, 'filled')
    xlabel('Average Brake Pressure')
    ylabel('|Deceleration| (m/s^2)')
    title('Brake Effectiveness'), grid on

    % --- μ vs Achieved Deceleration ---
    subplot(3,3,5)
    scatter(mu, abs(ax), 30, 'filled'), hold on
    plot(mu, mu*g, 'k--')
    xlabel('Friction Coefficient μ')
    ylabel('|Deceleration| (m/s^2)')
    title('Friction Envelope Check'), grid on
    legend('Data','μ·g limit','Location','best')

    % --- Reverse Thrust vs Speed ---
    subplot(3,3,6)
    scatter(Vg, RevAvg, 30, 'filled')
    xlabel('Ground Speed (m/s)')
    ylabel('Reverse Thrust Level')
    title('Reverse Thrust Effectiveness'), grid on

    % --- Brake Symmetry ---
    subplot(3,3,7)
    plot(time, BrakeDiff, 'LineWidth', 1.5)
    xlabel('Time (s)'), ylabel('Brake L - R')
    title('Brake Asymmetry'), grid on

    % --- Reverse Symmetry ---
    subplot(3,3,8)
    plot(time, RevDiff, 'LineWidth', 1.5)
    xlabel('Time (s)'), ylabel('Rev L - R')
    title('Reverse Asymmetry'), grid on

    % --- Ground Track ---
    subplot(3,3,9)
    plot(lon, lat, '-o')
    xlabel('Longitude'), ylabel('Latitude')
    title('Ground Track (40s)'), grid on

end
